open Mirage_types_lwt

open Lwt.Infix

module Client (S  : STACKV4) (CL : PCLOCK) (RES: Resolver_lwt.S) (CON: Conduit_mirage.S) = struct
  module Acme = Letsencrypt.Client.Make (Cohttp_mirage.Client)

  (* goes along, generates a private key, and a csr with hostname, the initiates
   http connection to let's encrypt staging, dns challenge, nsupdate, retrieves
   certificate.  this is then printed on stdout for now *)
  let gen_rsa seed =
    let seed = Cstruct.of_string seed in
    let g = Nocrypto.Rng.(create ~seed (module Generators.Fortuna)) in
    Nocrypto.Rsa.generate ~g 4096

  let start stack clock res ctx _ =
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
    let now = Ptime.v (CL.now_d_ps clock) in
    let solver = Letsencrypt.Client.default_dns_solver now send name dnskey in
    let sleep () = OS.Time.sleep_ns (Duration.of_sec 3) in
    Conduit_mirage.with_tls ctx >>= fun ctx ->
    let ctx = Cohttp_mirage.Client.ctx res ctx in
    Acme.get_crt ~ctx ~directory:(Uri.of_string "https://acme-staging.api.letsencrypt.org/directory") ~solver sleep account_key csr >|= function
    | Error e -> Logs.err (fun m -> m "error %s" e)
    | Ok cert -> Logs.info (fun m -> m "certificate: %s" cert)
end
