#!/bin/bash
set -x

while [ "$(docker exec -ti vault vault status | jq .initialized)" != "true" ]
do
	sleep 1
done

docker exec -ti vault vault kv put -mount=secret guestowner1/workload-id/secret secret=test
docker exec -ti vault vault kv get -mount=secret guestowner1/workload-id/secret

docker exec -ti vault sh -c 'tee readonly.hcl <<EOF
 path "secret/data/guestowner1/workload-id/*" {
   capabilities = ["read"]
 }
EOF
'
docker exec -ti vault vault policy write kbs readonly.hcl

VAULT_TOKEN=$(docker exec -ti vault vault token create -policy="kbs" -field=token)
echo $VAULT_TOKEN
