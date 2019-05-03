open Lwt.Infix

module Acme_cli = Acme_client.Make(Cohttp_lwt_unix.Client)

let dns_out ip cs =
  let out = Lwt_unix.(socket PF_INET SOCK_DGRAM 0) in
  let server = Lwt_unix.ADDR_INET (ip, 53) in
  let bl = Cstruct.len cs in
  Lwt_unix.sendto out (Cstruct.to_bytes cs) 0 bl [] server >>= fun n ->
  (* TODO should listen for a reply from NS, report potential errors and retransmit if UDP frame got lost *)
  if n = bl then Lwt.return_ok () else Lwt.return_error (`Msg "couldn't send nsupdate")

let sleep () = Lwt_unix.sleep 5.

let err_to_msg = function
  | Ok a -> Ok a
  | Error e -> Error (`Msg e)

let doit endpoint account_key solver sleep csr =
  Acme_cli.initialise ~directory:(Uri.of_string endpoint) account_key >>= function
  | Ok t -> Acme_cli.sign_certificate ~solver t sleep csr
  | Error e -> Lwt.return_error e

let main _ rsa_pem csr_pem _acme_dir ip key endpoint cert zone =
  let open Rresult.R.Infix in
  let r =
    let rsa_pem, csr_pem, cert = Fpath.(v rsa_pem, v csr_pem, v cert) in
    Bos.OS.File.read rsa_pem >>= fun rsa_pem ->
    Bos.OS.File.read csr_pem >>= fun csr_pem ->
    Bos.OS.File.exists cert >>= function
    | true -> Error (`Msg ("output file " ^ Fpath.to_string cert ^ " already exists"))
    | false -> match Dns.Dnskey.name_key_of_string key with
      | Error e -> Error e
      | Ok (keyname, key) ->
        (try Ok (Unix.inet_addr_of_string ip) with Failure e -> Error (`Msg e)) >>= fun ip ->
        err_to_msg (Primitives.priv_of_pem rsa_pem) >>= fun account_key ->
        err_to_msg (Primitives.csr_of_pem csr_pem) >>= fun request ->
        let now = Ptime_clock.now () in
        let zone = match zone with
          | None -> Domain_name.drop_labels_exn ~amount:2 keyname
          | Some x -> Domain_name.of_string_exn x
        in
        Nocrypto_entropy_unix.initialize () ;
        let random_id = Randomconv.int16 Nocrypto.Rng.generate in
        let solver = Acme_client.default_dns_solver random_id now (dns_out ip) ~keyname key ~zone in
        match Lwt_main.run (doit endpoint account_key solver sleep request) with
        | Error e -> Error e
        | Ok t ->
          Logs.info (fun m -> m "Certificate downloaded");
          Bos.OS.File.write cert (Cstruct.to_string @@ X509.Certificate.encode_pem t)
  in
  match r with
  | Ok _ -> `Ok ()
  | Error (`Msg e) ->
    Logs.err (fun m -> m "Error %s" e) ;
    `Error ()

let setup_log style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (Logs_fmt.reporter ())

open Cmdliner

let rsa_pem =
  let doc = "File containing the PEM-encoded RSA private key." in
  Arg.(value & opt string "priv.key" & info ["account-key"] ~docv:"FILE" ~doc)

let csr_pem =
  let doc = "File containing the PEM-encoded CSR." in
  Arg.(value & opt string "certificate.csr" & info ["csr"] ~docv:"FILE" ~doc)

let acme_dir =
  let default_path = "/var/www/html/.well-known/acme-challenge/" in
  let doc =
    "Base path for where to write challenges. " ^
    "For letsencrypt, it must be the one serving " ^
    "http://example.com/.well-known/acme-challenge/" in
  Arg.(value & opt string default_path & info ["acme_dir"] ~docv:"DIR" ~doc)

let ip =
  let doc = "ip address of DNS server" in
  Arg.(value & opt string "" & info ["ip"] ~doc)

let key =
  let doc = "nsupdate key" in
  Arg.(value & opt string "" & info ["key"] ~doc)

let endpoint =
  let doc = "ACME endpoint" in
  Arg.(value & opt string (Uri.to_string Acme_common.letsencrypt_staging_url) & info ["endpoint"] ~doc)

let zone =
  let doc = "Zone" in
  Arg.(value & opt (some string) None & info ["zone"] ~doc)

let cert =
  let doc = "filename where to store the certificate" in
  Arg.(value & opt string "certificate.pem" & info ["cert"] ~doc)

let setup_log =
  Term.(const setup_log
        $ Fmt_cli.style_renderer ()
        $ Logs_cli.level ())

let info =
  let doc = "just another ACME client" in
  let man = [
      `S "DESCRIPTION"; `P "This is software is experimental. Don't use it.";
      `S "BUGS"; `P "Email bug reports to <maker@tumbolandia.net>";
    ] in
  Term.info "oacmel" ~version:"%%VERSION%%" ~doc ~man

let () =
  let cli = Term.(const main $ setup_log $ rsa_pem $ csr_pem $ acme_dir $ ip $ key $ endpoint $ cert $ zone) in
  match Term.eval (cli, info) with
  | `Error _ -> exit 1
  | _        -> exit 0
