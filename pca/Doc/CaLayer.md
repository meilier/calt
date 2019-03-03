# PCA

## CA Layer

**Name Rule**
cakey.pem
cacert.pem

account1.csr
account1.pem

tls1.csr
tls1.pem

.
├── certs
│   ├── account
│   │   └── account0.pem
│   └── tls
│       └── tls1.pem
├── crl
│   └── invoke.crl
├── crlnumber
├── crlnumber.old
├── index.txt
├── index.txt.attr
├── index.txt.attr.old
├── index.txt.old
├── newcerts
│   ├── 1234.pem
│   └── 1235.pem
├── private
│   ├── cacert.pem
│   └── cakey.pem
├── requests
│   ├── account
│   │   └── account1.csr
│   └── tls
│       └── tls1.csr
├── serial
└── serial.old

## Client Layer

**Name Rule**
account.key.pem
account.csr
account.pem

tls.key.pem
tls.csr
tls.pem

.
├── certs
│   ├── account
│   │   └── account.key.pem
│   └── tls
│       └── tls.key.pem
├── crl
├── openssl.cnf
└── requests
    ├── account
    │   └── account.csr
    └── tls
        └── tls.csr