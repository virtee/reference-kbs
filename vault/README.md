# Example how to use Vault for testing the KBS and the secret unlocking

## Run container and set dev environment
For simplification we run all the containers without network namespace and the ports are directly mapped on the host.
```bash
./start-vault.sh
```
For all the following commands, you can get the curl version with the http request with the flag `--output-curl-string`.

In order to use Vault cli, either exec in the vault container or start a new one from the repository directory with:
```bash
docker run -e 'VAULT_ADDR=http://127.0.0.1:8200' -e 'VAULT_TOKEN=myroot' \
  -ti --network host \
  --entrypoint sh vault
```

## Create a secret in Vault
This tutorial uses the v2 of the Vault API available from version 1.11.
Using version `v2` in Vault. Verify if it is enabled:
```bash
$ vault secrets list -detailed |grep secret
cubbyhole/    cubbyhole    cubbyhole_76474b5c    n/a            n/a        false             local          false        false                      map[]             per-token private secret storage                           da1c7486-780a-69a1-68be-7e08aaf54159
secret/       kv           kv_00ba64fb           system         system     false             replicated     false        false                      map[version:2]    key/value secret storage                                   e18504b8-ad93-640d-51f9-78a5adb80c93
# OR
curl --header "X-Vault-Token: $VAULT_TOKEN" \
  $VAULT_ADDR/v1/sys/mounts | 
   jq -r '."secret/".options.version'
```
Create the secret:
```bash
$ vault kv put -mount=secret guestowner1/workload-id/secret password=test
=============== Secret Path ===============
secret/data/guestowner1/workload-id/secret

======= Metadata =======
Key                Value
---                -----
created_time       2022-08-03T11:43:55.901333334Z
custom_metadata    <nil>
deletion_time      n/a
destroyed          false
version            1
```
Read back the secret
```bash
$ vault kv get -mount=secret guestowner1/workload-id/secret
=============== Secret Path ===============
secret/data/guestowner1/workload-id/secret

======= Metadata =======
Key                Value
---                -----
created_time       2022-08-03T11:43:55.901333334Z
custom_metadata    <nil>
deletion_time      n/a
destroyed          false
version            1

====== Data ======
Key         Value
---         -----
password    test
```

## Give access to the KBS to the guest owner secret
This steps follow the [Vault tutorial](https://learn.hashicorp.com/tutorials/vault/static-secrets) for the static secrets.

Create readonly policy for the kbs
```bash
$ tee readonly.hcl <<EOF
 path "secret/data/guestowner1/workload-id/*" {
   capabilities = ["read"]
 }
EOF
$  vault policy write kbs readonly.hcl 
Success! Uploaded policy: kbs
$ APPS_TOKEN=$(vault token create -policy="kbs" -field=token)
$ echo $APPS_TOKEN
hvs.CAESIAzsj8eX24cpLANyBsFrt5SqXnwWKKA2oXlwRxPw3pUlGh4KHGh2cy52eWZ0QmVhdG5wOXh0YkVwbzRiemlZYlE
```
Simulate how the KBS should read the secret:
```bash
$ VAULT_TOKEN=$APPS_TOKEN  vault kv get -mount=secret guestowner1/workload-id/secret
```
