open Mirage

(* what should be the boot parameters?
   - DNS update key, zone, and IP address
   - hostname and certificate key seed
   - account key seed
*)

let dns_keys =
  let doc = Key.Arg.info ~doc:"nsupdate key (name:type:value,...)" ["dns-keys"] in
  Key.(create "dns-keys" Arg.(opt (list string) [] doc))

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
    abstract dns_keys ; abstract dns_server ; abstract hostname ;
    abstract account_key_seed ; abstract cert_key_seed
  ]

let address =
  let network = Ipaddr.V4.Prefix.of_address_string_exn "10.0.42.10/24"
  and gateway = Ipaddr.V4.of_string "10.0.42.1"
  in
  { network ; gateway }

let net =
  if_impl Key.is_unix
    (socket_stackv4 [Ipaddr.V4.any])
    (static_ipv4_stack ~config:address ~arp:farp default_network)

let packages = [
  package "x509" ;
  package "duration" ;
  package "logs" ;
  package "cohttp-mirage" ;
  package "letsencrypt" ;
  package ~sublibs:[ "mirage" ; "server" ] "udns" ;
  package "hex" ;
  package "randomconv" ;
]

let client =
  foreign ~deps:[abstract nocrypto] ~keys ~packages "Unikernel.Client" @@
  random @-> pclock @-> mclock @-> time @-> stackv4 @-> resolver @-> conduit @-> job

let () =
  let res_dns = resolver_dns net in
  let conduit = conduit_direct net in
  register "letsencrypt-client"
    [ client $ default_random $ default_posix_clock $ default_monotonic_clock $ default_time $ net $ res_dns $ conduit ]
