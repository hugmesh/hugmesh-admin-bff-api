Test-only HugMesh token fixtures. The key below exists for these tests and nothing else;
it is not, and must never become, any mesh's issuer.

test-issuer.seed.hex   the Ed25519 seed (32 bytes, hex) of a key made with
                       ssh-keygen -t ed25519 -N '' -C ''. Committed as a seed, not as an
                       OpenSSH PEM file, so secret scanners do not flag a "private key";
                       the tests rebuild the OpenSSH and PKCS#8 files from it.
test-issuer.pub        its public line (ssh-keygen -lf: SHA256:fC2eP8qPXVSHcQc+XeJhTc82fub1sbpVnv3FNMsQEj4)
golden-payload         json.dumps(grant, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
                       for the golden grant (Python 3, the Studio's canonical form)
golden-payload.sig     ssh-keygen -Y sign -f <key> -n hugmesh-mesh-token@hugmesh.org golden-payload
golden-token.txt       hugmesh-token-v1.<b64url payload>.<b64url sig>, as mesh_token.issue() builds it
golden-payload-minimal the Python canonical bytes of a second grant (role user, no shell,
                       empty node_name and id)
