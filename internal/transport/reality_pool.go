package transport

// realityPublicPool is the embedded set of server Reality public keys (base64
// X25519). When a client has no explicit [reality].public_key, it picks one of
// these at random per connection, so no key needs to be distributed to clients
// manually. The matching PRIVATE keys are deployed to servers via
// [reality].private_keys (see `supervpn-server reality-genpool`).
//
// SECURITY NOTE: these are PUBLIC keys, but in the Reality scheme the server's
// public key is the client-side credential. Shipping it in the (public) client
// binary protects against generic active probing, yet a targeted adversary who
// extracts the pool can defeat the dest fallback. The inner supervpn password
// auth still fully protects VPN access.
//
// This file is generated; edit via reality-genpool rather than by hand.
var realityPublicPool = []string{
	"+0YF7mC9hdOISLkkAwTvbjqhevYAwmaEHkE/fpkKI3o=",
	"YTAamDYyJYjkD9yVCqlV95gvrJM2cX4osxHh9d8rxFQ=",
	"e4595/OkiWPpCrSERBROMen+GAKnZ3UQcV4gYjoRBzQ=",
	"yszTKT1BfTt8JIAmNpcUJ9M7W/DY3Re9JxouhZPkCkk=",
	"vDwEBBzf4DdKVLCSWe0rzMU8Nsw1YQ0z0LVr9fRvnnQ=",
	"URu+OkJbOb8a2keel3ALu9ViKagE6SaOci3paOQ3Ujg=",
	"Hqr3g+7/ZdQ0hRgMwhs8mZXx0Ie2GrQjZ2Fww8GOwVo=",
	"a5S5gx0rO3ZYFLg8xFU8ADLQDI3uLnjCVOk7l9WohEI=",
	"5+Maz6p5MgsZj6Q2XiXxfFFFJNaFcyOfp7wNB3FYExg=",
	"kYXM83U9PtPEHE8ECiK0mklESRMzJ4490h6uS6rMq2E=",
	"lmPJN1Ah0t7yVKayxEpz+5Wuc378NeAl8kRTdihXxVI=",
	"HQT6rnnrooVu66my9nlV/D9uk7FQ4Yw4/lXZm9bvxTs=",
	"v9mfOS63iPvR/9IWpTzUye8HZ20MWqoOel7LikpacBw=",
	"vK/ynOpHCMQmiRbXX/6MNm1sBfIFzB4LNf0S7J9TsG4=",
	"HsDwWh/xch5IzB+f072n0jHK39tyJCltZ0ptXEkqInk=",
	"MHW60rdHAR5TIOVUJqHjB9hxWihn+cKYkhapgbjpmg8=",
	"UKHMopn/nsdHb03PwkpC3+vthsv31II8kaB29bV/0D8=",
	"4gaguc+9svluoE5/Lq90ze+hiAMXdUmxg7GPvH5aE0U=",
	"/yIr0aMFy1hPfpeZtrrFC5U5AMk2uTQXFQJ5WOsvrlM=",
	"5niNZHKjNjNVN2NWqrunRRlWhBnlk27iQKU3mT5bDg8=",
	"Zlf4FB6wYfQx0Vyj1/kAx+K3EREesmLV3cfHF3LF2D8=",
	"cS2RrpTLr8TaBrQzJwdUB6EMwj7yXm6Jg76bllIDiAQ=",
	"ss4fcFi35k17eVLg6ezIfQpFQD6p9lAxaTf4fchwOXA=",
	"mTYaG4xRbUUVaHqH8tNEjpr3Q49h1BDy9QKFviPke2Y=",
	"fzF7WjciF+sIxHnwJOOSMUv22HsoYPHoEwgAHjtrLiM=",
	"7OFI8eIJLkSxZZjidyw4B8YOnzJMd5IemcXIDMZ3/Cg=",
	"iZuY9fFJ+gy24CvHXwVZ70BqjoLRy3LzBcX6zAe7mRY=",
	"qQLRQRLWMalXVoW5OCHiocD+7j+jgosjoVc4nJ18czI=",
	"1/NOvQbNkFKNKSfBhFEAmtjrFE+TQ6Ot6aqv3zTi4ko=",
	"55HrBvpcP0tP9kDTeybAHzDierftT9arDhubQsZHZj0=",
	"ht5+X20a1bPHONj6hhWHiw7vbX2wru+4G2NmjXF3FE8=",
	"ji8v16gRhuYCcxDph08PQo7hyqWq/eZsgZCbireUVwU=",
	"I/OEiDZo7NHAt43o0i/zS8LBeqIRwVCrUBfQIKw8qjk=",
	"Xv6E5jp0qNgfB0HYRH0aAi/tF5r7yNRPDSbTIPo9vAY=",
	"tsQ0L4pH5E1I3PJkjlpQ00NvrszhkXp+Pp/eAMKC42A=",
	"gJZER4SyA/754GqQcLVF9adeNPlwpiqbUA9RzvrbpQo=",
	"CzkLjv4OsBQjWpfEmxP7imNLloQ6yEh4S42DoDrFamQ=",
	"MySz++gGvO8zxJpEY/sUqtD+2+efQZRqn2bKIFo2ujE=",
	"eCelbSyCuIMzPArnIA0pCgPO8zbebbEGnxBirPAxV0U=",
	"xm+MXfXSjmftdhSEK/SmgFmvwT3bjvFrijtce4h7jTg=",
	"opfCx7LidGlP5KEfubBnEIL856TATVUIUuNDIBCkvAo=",
	"oYMuLG+R5/GJKADqh58GrsCkeREf32tBa6EthFBMGCA=",
	"ukO0Oyhfge7279Nh+4NE7HWUh4k0CzbcZuxmvUsxRTo=",
	"cVrLT0voOM4wjpIaQQAhkaNBvcAOm/EuI4M6pBUs0Sc=",
	"TkyD5J0A2PhgW6DOFtG4q48kOAAqk/TiybsIAYFr/2s=",
	"mFii4XItBrAQvo45+gPj2DLseyyFJLX5fp0CHzQX4gs=",
	"/80SuL6e2RuD/apn1kMMZUi1JtxmIa3doeTft4vZ7VE=",
	"22uDfUnWgTGC1b6M7BpN4BAxbyS0aIXOgqp4jKWgqis=",
	"HGIGx516HyqjWGz+KtzT8OEk1cVdnpS9SP3DnBwsQwM=",
	"/XnNBcn81S+NIOitm3QOjmgeDoYaFhiY2bIgctgK7Dc=",
	"Q/qOszZA+r8eZi/vpEaB1lYkpgkfMeqddnDK0+iDrxA=",
	"sxzPP/VoD0sEjRcjs5Y+qLTbAylJAFVuOz27tMEg2x4=",
	"FiwJ7OqVxnM9SgluMBdDBnzj6/ZIRgEwsBGAwMVnuRI=",
	"6/RKiIuSRTclgeOpYZX7yKnNWqmGDd3gH1olkIObx3k=",
	"17QVfnf4XWhB+BAii/mvK5WziLHyWxS7yDXLTWRF9CM=",
	"tB+55jgUTREzp9Vc73gHv5idmff1FzEriC4NCagE/h8=",
	"v1x1aMOqm7ZuKXgSRCznRGq2t8HP2w7FomueVUJLjGs=",
	"YZeG5DD/nAuyX+OU3+wCi+/P930sdPMDVy8tE0ed23Q=",
	"met/hONcJEoTemmTfmjhQckZ2G+9e1XVh1ZO/yBLTFc=",
	"YvSYCwD0OUpx3vqIOhzJZAdavA/hH4ZheC2V6DuKXxs=",
	"Q/UqX79oMZh/Zbe0fN0u/78/5YPnQ5v38JH4VkNXZxI=",
	"GFZoyPFWz2HS4sa5aBYXZBp7kmNwwryHxg+M3OvRsgI=",
	"Hyg6mYymtPGrkp7bHC1DQKpSqIZrdiRsLq6Z1129lUg=",
	"xS8dh2+LHZzrAB1FafayL/2nxQsHwS0VWJ8czseT2jA=",
}
