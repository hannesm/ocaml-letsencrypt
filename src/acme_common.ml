type directory_t = {
  directory   : Uri.t;
  new_authz   : Uri.t;
  new_reg     : Uri.t;
  new_cert    : Uri.t;
  revoke_cert : Uri.t;
}

let domains_of_csr csr =
  let open X509 in
  let info = CA.info csr in
  let subject_alt_names =
    match List.find_opt (function `Extensions _ -> true | _ -> false) info.X509.CA.extensions with
    | Some (`Extensions exts) ->
      begin match Extension.(find Subject_alt_name exts) with
        | None -> []
        | Some (_, things) ->
          List.(concat (map (function `DNS name -> [ name ] | _ -> []) things))
      end
    | _ -> []
  in
  match subject_alt_names with
  | [] ->
    (* XXX: I'm assuming there is always exactly one CN in a subject. *)
    info.X509.CA.subject
    |> List.find (function
        | `CN _ -> true
        | _ -> false)
    |> (function
        | `CN name -> [name]
        | _ -> assert false)
  | _ -> subject_alt_names

let letsencrypt_url = Uri.of_string
    "https://acme-v01.api.letsencrypt.org/directory"

let letsencrypt_staging_url = Uri.of_string
    "https://acme-staging.api.letsencrypt.org/directory"
