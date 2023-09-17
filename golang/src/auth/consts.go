package auth

import "sharpstorm/srp-auth/auth/srp"

var SRP_GROUP = &srp.GROUP_3072
var SRP_HASH = srp.SHA512

const handshakeIdLength = 64
