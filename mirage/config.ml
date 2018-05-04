open Mirage

(* what should be the boot parameters?
   - DNS update key, zone, and IP address
   - hostname and certificate key seed
   - account key seed
*)

let dns_key =
  let doc = Key.Arg.info ~doc:"nsupdate key (name:type:value,...)" ["dns-key"] in
  Key.(create "dns-key" Arg.(opt string "" doc))

let dns_server =
  let doc = Key.Arg.info ~doc:"dns server IP" ["dns-server"] in
  Key.(create "dns-server" Arg.(opt ipv4_address Ipaddr.V4.localhost doc))

let hostname =
  let doc = Key.Arg.info ~doc:"hostname" ["hostname"] in
  Key.(create "hostname" Arg.(opt string "" doc))

let account_key_seed =
  let doc = Key.Arg.info ~doc:"account key seed" ["account-key-seed"] in
  Key.(create "account-key-seed" Arg.(opt string "" doc))

let cert_key_seed =
  let doc = Key.Arg.info ~doc:"certificate key seed" ["certificate-key-seed"] in
  Key.(create "certificate-key-seed" Arg.(opt string "" doc))

let keys = Key.[
    abstract dns_key ; abstract dns_server ; abstract hostname ;
    abstract account_key_seed ; abstract cert_key_seed
  ]

let packages = [
  package "x509" ;
  package "duration" ;
  package "logs" ;
  package "cohttp-mirage" ;
  package "letsencrypt" ;
]

let client =
  foreign ~deps:[abstract nocrypto] ~keys ~packages "Unikernel.Client" @@
  stackv4 @-> pclock @-> resolver @-> conduit @-> job

let () =
  let stack = generic_stackv4 default_network in
  let res_dns = resolver_dns stack in
  let conduit = conduit_direct stack in
  register "letsencrypt-client" [ client $ stack $ default_posix_clock $ res_dns $ conduit ]
