storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_cert_file = "/certs/vault.pem"
  tls_key_file  = "/certs/vault-key.pem"
}

ui = true
disable_mlock = true
api_addr = "https://vault:8200"
cluster_addr = "https://vault:8201"
