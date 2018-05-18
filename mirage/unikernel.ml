open Mirage_types_lwt

open Lwt.Infix

module Client (R : RANDOM) (P : PCLOCK) (M : MCLOCK) (T : TIME) (S : STACKV4) (RES: Resolver_lwt.S) (CON: Conduit_mirage.S)= struct
  module Acme = Letsencrypt.Client.Make (Cohttp_mirage.Client)

  module Dns = Dns_mirage.Make(R)(P)(M)(T)(S)

  (* goes along, generates a private key, and a csr with hostname, the initiates
   http connection to let's encrypt staging, dns challenge, nsupdate, retrieves
   certificate.  this is then printed on stdout for now *)
  let gen_rsa seed =
    let seed = Cstruct.of_string seed in
    let g = Nocrypto.Rng.(create ~seed (module Generators.Fortuna)) in
    Nocrypto.Rsa.generate ~g 4096

  let start' _random pclock _mclock _ stack res ctx _ =
    let name, dnskey =
      match Astring.String.cut ~sep:":" (Key_gen.dns_key ()) with
      | None -> invalid_arg "couldn't parse dnskey"
      | Some (name, key) ->
        match Dns_name.of_string ~hostname:false name, Dns_packet.dnskey_of_string key with
        | Error _, _ | _, None -> invalid_arg "failed to parse dnskey"
        | Ok name, Some dnskey -> (name, dnskey)
    in
    let private_key = gen_rsa (Key_gen.certificate_key_seed ()) in
    let csr = X509.CA.request [`CN (Key_gen.hostname ()) ] (`RSA private_key) in
    let account_key = gen_rsa (Key_gen.account_key_seed ()) in
    let send data =
      let dst = Key_gen.dns_server () in
      S.UDPV4.write ~dst ~dst_port:53 (S.udpv4 stack) data >>= function
      | Ok () -> Lwt.return (Ok ())
      | Error e -> Lwt.return (Error (Fmt.to_to_string S.UDPV4.pp_error e))
    in
    let now = Ptime.v (P.now_d_ps pclock) in
    let solver = Letsencrypt.Client.default_dns_solver now send name dnskey in
    let sleep () = OS.Time.sleep_ns (Duration.of_sec 3) in
    Conduit_mirage.with_tls ctx >>= fun ctx ->
    let ctx = Cohttp_mirage.Client.ctx res ctx in
    Acme.initialise ~ctx ~directory:Letsencrypt.letsencrypt_staging_url account_key >>= function
    | Error e -> Logs.err (fun m -> m "error %s" e) ; Lwt.return_unit
    | Ok t ->
      Acme.sign_certificate ~ctx ~solver t sleep csr >|= function
      | Error e -> Logs.err (fun m -> m "error %s" e)
      | Ok cert -> Logs.info (fun m -> m "certificate: %s" (Cstruct.to_string @@ X509.Encoding.Pem.Certificate.to_pem_cstruct1 cert))


  (* part II:
     establish an authenticated channel to receive signing requests and provide signed certificates
     since we already use DNS in here, we use DNS as authenticated channel
     not the unikernel which wants a certificate has to send us a nsupdate request with the csr
     we communicate via http(s) with let's encrypt and nsupdate to the authoritative nameserver for solving the challenge
     once we download the pem, we push it via nsupdate to the authoritative

     plan b: act as a hidden dns secondary and receive notifies, sweep through the zone for signing requests without corresponding (non-expired) certificate

     this means we've to care about tlsa *)

  (*
     we have additional logic/complexity, namely a DNS (TCP-only?) listener
     we also need a dns key for the authentication (plan b says a transfer key)

     Acme.initialise is done just after boot

     then either for an nsupdate or for a notify is waited and acted upon

     for each new tlsa record where selector = private and the content can be
       parsed as csr with a domain name we have keys for (or update uses the
       right key)
 *)

  let start _random pclock mclock _ stack res ctx _ =
    let key_name, dnskey =
      match Astring.String.cut ~sep:":" (Key_gen.dns_key ()) with
      | None -> invalid_arg "couldn't parse dnskey"
      | Some (name, key) ->
        match Dns_name.of_string ~hostname:false name, Dns_packet.dnskey_of_string key with
        | Error _, _ | _, None -> invalid_arg "failed to parse dnskey"
        | Ok name, Some dnskey -> (name, dnskey)
    in
    let account_key = gen_rsa (Key_gen.account_key_seed ()) in
    let send_and_wait data =
      let dst = Key_gen.dns_server () in
      Logs.debug (fun m -> m "writing to %a" Ipaddr.V4.pp_hum dst) ;
      let tcp = S.tcpv4 stack in
      S.TCPV4.create_connection tcp (dst, 53) >>= function
      | Error e ->
        Logs.err (fun m -> m "failed to create connection to NS: %a" S.TCPV4.pp_error e) ;
        Lwt.return (Error (Fmt.to_to_string S.TCPV4.pp_error e))
      | Ok flow ->
        Dns.send_tcp flow data >>= function
        | Error () ->
          Lwt.return (Error "error while sending nsupdate")
        | Ok () ->
          (* we expect a single reply! *)
          Dns.read_tcp (Dns.of_flow flow) >>= function
          | Error () ->
            Logs.err (fun m -> m "failed to read") ;
            Lwt.return (Error "error while reading nsupdate reply")
          | Ok buf ->
            (* now verify that buf was a good one *)
            match Dns_packet.decode buf with
            | Error e ->
              Logs.err (fun m -> m "error %a while decoding DNS answer"
                           Dns_packet.pp_err e) ;
              Lwt.return (Error (Fmt.to_to_string Dns_packet.pp_err e))
            | Ok ((hdr, `Update u), Some off) when hdr.Dns_packet.rcode = Dns_enum.NoError ->
              Logs.debug (fun m -> m "likely a good update") ;
              (* should verify signature *)
(*              let tsig = Cstruct.shift buf off in
                if Dns_tsig.verify ~mac:??? <time> (`Update u) hdr <name> ~key:?? .. ?? then *)
              Lwt.return (Ok ())
(*              else
                Lwt.return (Error "couldn't verify signature on nsupdate reply") *)
            | Ok (t, _) ->
              Logs.err (fun m -> m "bad update: %a" Dns_packet.pp t) ;
              Lwt.return (Error "bad update")
    (* in all cases: safely close flow! remove from in_flight (also retry on
       connection failure [and exit on nsupdate notauth!?]) *)
    in
    Conduit_mirage.with_tls ctx >>= fun ctx ->
    let ctx = Cohttp_mirage.Client.ctx res ctx in
    Acme.initialise ~ctx ~directory:Letsencrypt.letsencrypt_staging_url account_key >>= function
    | Error e -> Logs.err (fun m -> m "error %s" e) ; Lwt.return_unit
    | Ok le ->
      let t =
        let data =
          let zone = (* drop first two labels of dnskey *)
            let arr = Dns_name.to_array key_name in
            Dns_name.of_array Array.(sub arr 0 (length arr - 2))
          in
          let soa = 300l, { Dns_packet.nameserver = zone ; hostmaster = zone ;
                            serial = 1l ; refresh = 300l ; retry = 300l ;
                            expiry = 3000l ; minimum = 300l}
          in
          Dns_trie.insert key_name Dns_map.(V (K.Dnskey, [ dnskey ]))
            (Dns_trie.insert zone Dns_map.(V (K.Soa, soa)) Dns_trie.empty)
        in
        UDns_server.Primary.create ~a:[UDns_server.tsig_auth]
          ~tsig_verify:Dns_tsig.verify ~tsig_sign:Dns_tsig.sign
          ~rng:R.generate data
      in
      let state = ref t in
      (* TODO use a map with number of attempts *)
      let in_flight = ref Astring.String.Set.empty in
      Logs.info (fun m -> m "initialised lets encrypt") ;

      let handle_csrs () =

        let react_change name (_, tlsas) () =
          let is_csr t =
            t.Dns_packet.tlsa_selector = Dns_enum.Tlsa_selector_private &&
            t.Dns_packet.tlsa_matching_type = Dns_enum.Tlsa_no_hash
          and is_cert t =
            t.Dns_packet.tlsa_selector = Dns_enum.Tlsa_full_certificate &&
            t.Dns_packet.tlsa_matching_type = Dns_enum.Tlsa_no_hash &&
            t.Dns_packet.tlsa_cert_usage = Dns_enum.Domain_issued_certificate
          and matches csr cert =
            (* parse csr, parse cert: match public keys, match validity of cert *)
            Logs.warn (fun m -> m "not yet implemented: whether csr matches cert") ;
            true
          in
          match List.filter is_csr tlsas, List.filter is_cert tlsas with
          | [], _ -> Logs.info (fun m -> m "no private selector")
          | [csr], [cert] when matches csr cert ->
            Logs.info (fun m -> m "cert exists for csr")
          | [tlsa], _ ->
            begin
              match X509.Encoding.parse_signing_request tlsa.Dns_packet.tlsa_data with
              | exception e ->
                Logs.err (fun m -> m "couldn't parse signing request: %s"
                             (Printexc.to_string e))
              | None -> Logs.err (fun m -> m "couldn't parse signing request")
              | Some csr ->
                match List.find (function `CN _ -> true | _ -> false) (X509.CA.info csr).X509.CA.subject with
                | exception Not_found -> Logs.err (fun m -> m "cannot find name of signing request")
                | `CN nam ->
                  begin match Dns_name.of_string nam with
                    | Error (`Msg msg) -> Logs.err (fun m -> m "error %s while creating domain name of %s" msg nam)
                    | Ok dns_name ->
                      if not (Dns_name.equal dns_name name) then
                        Logs.err (fun m -> m "csr cn %a doesn't match dns %a" Dns_name.pp dns_name Dns_name.pp name)
                      else if Astring.String.Set.mem nam !in_flight then
                        Logs.err (fun m -> m "request with %s already in-flight" nam)
                      else begin
                        in_flight := Astring.String.Set.add nam !in_flight ;
                        (* request new cert in async *)
                        Lwt.async (fun () ->
                            let sleep () = OS.Time.sleep_ns (Duration.of_sec 3) in
                            let now = Ptime.v (P.now_d_ps pclock) in
                            let solver = Letsencrypt.Client.default_dns_solver now send_and_wait key_name dnskey in
                            Acme.sign_certificate ~ctx ~solver le sleep csr >|= function
                            | Error e -> Logs.err (fun m -> m "error %s" e)
                            | Ok cert ->
                              let certificate = X509.Encoding.cs_of_cert cert in
                              Logs.info (fun m -> m "certificate received") ;
                              let trie = UDns_server.Primary.data !state in
                              match Dns_trie.lookup_direct name Dns_map.K.Tlsa trie with
                              | Ok (ttl, tlsas) ->
                                let tlsa = { Dns_packet.tlsa_cert_usage = Dns_enum.Domain_issued_certificate ;
                                             tlsa_selector = Dns_enum.Tlsa_full_certificate ;
                                             tlsa_matching_type = Dns_enum.Tlsa_no_hash ;
                                             tlsa_data = certificate }
                                in
                                let others = List.filter (fun t -> not (is_cert t)) tlsas in
                                let trie = Dns_trie.insert name Dns_map.(V (K.Tlsa, (ttl, tlsa :: others))) trie in
                                state := UDns_server.Primary.with_data !state trie ;
                                in_flight := Astring.String.Set.remove nam !in_flight ;
                              | Error e ->
                                Logs.err (fun m -> m "couldn't find tlsa for %a: %a" Dns_name.pp name Dns_trie.pp_e e))
                      end
                  end
                | _ -> Logs.err (fun m -> m "cannot find common name of signing request")
            end
          | _, _ -> Logs.err (fun m -> m "not prepared for this task")
        in

        match Dns_trie.folde Dns_name.root Dns_map.K.Tlsa (UDns_server.Primary.data !state) react_change () with
        | Ok () -> ()
        | Error e -> Logs.warn (fun m -> m "error %a while folding" Dns_trie.pp_e e)
      in

      let tcp_cb flow =
        let dst_ip, dst_port = S.TCPV4.dst flow in
        Logs.info (fun m -> m "tcp connection from %a:%d" Ipaddr.V4.pp_hum dst_ip dst_port) ;
        let f = Dns.of_flow flow in
        let rec loop () =
          Dns.read_tcp f >>= function
          | Error () -> Lwt.return_unit
          | Ok data ->
            let now = Ptime.v (P.now_d_ps pclock) in
            let elapsed = M.elapsed_ns mclock in
            let t, answer, _ = UDns_server.Primary.handle !state now elapsed `Tcp dst_ip data in
            state := t ;
            (* here we fold over TLSA *)
            handle_csrs () ;
            match answer with
            | None -> Logs.warn (fun m -> m "empty answer") ; loop ()
            | Some answer ->
              Dns.send_tcp flow answer >>= function
              | Ok () -> loop ()
              | Error () -> Lwt.return_unit
        in
        loop ()
      in
      S.listen_tcpv4 stack ~port:53 tcp_cb ;
      S.listen stack

end
