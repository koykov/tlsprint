package tlsvector

//go:generate tlsvecgen --cipher-suites=https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv --dst=cipher_suites_repo.go
//go:generate tlsvecgen --extensions=https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values-1.csv --dst=extensions_repo.go
//go:generate tlsvecgen --elliptic-curves=https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv --dst=elliptic_curves_repo.go
//go:generate tlsvecgen --signature-algorithms=https://www.iana.org/assignments/tls-parameters/tls-parameters-16.csv --dst=signature_algorithms_repo.go
//go:generate tlsvecgen --client-certificate-types=https://www.iana.org/assignments/tls-parameters/tls-parameters-2.csv --dst=client_certificate_types_repo.go
//go:generate tlsvecgen --ec-point-formats=https://www.iana.org/assignments/tls-parameters/tls-parameters-9.csv --dst=ec_point_formats_repo.go
