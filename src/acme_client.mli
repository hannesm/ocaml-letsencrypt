type solver_t

type challenge_t = private {
  url: Uri.t;
  token: string;
}


val default_dns_solver : Ptime.t -> (Cstruct.t -> (unit, string) result Lwt.t) -> Dns_name.t -> Dns_packet.dnskey -> solver_t
val default_http_solver : solver_t

module Make (Client : Cohttp_lwt.S.Client) : sig
  val get_crt :
    ?ctx:Client.ctx ->
    ?directory:Uri.t -> ?solver:solver_t ->
    (unit -> unit Lwt.t) -> Nocrypto.Rsa.priv -> X509.CA.signing_request ->
    (string, string) Result.result Lwt.t
end
