package tlsvector

//go:generate tlsvecgen --cipher-suites=https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv --dst=cipher_suites_repo.go
//go:generate tlsvecgen --extensions=https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values-1.csv --dst=extensions_repo.go
//go:generate tlsvecgen --elliptic-curves=https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv --dst=elliptic_curves_repo.go
