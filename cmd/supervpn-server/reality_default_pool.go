package main

// defaultRealityPrivatePool is the built-in Reality private-key pool used when
// the server config specifies no private_key / private_keys. It matches the
// PUBLIC pool embedded in clients (internal/transport/reality_pool.go), so a
// zero-config server and a stock client interoperate out of the box.
//
// SECURITY NOTE: this default pool is committed to the (public) repo and shipped
// in the server binary, so it is effectively public. It protects against generic
// active probing only. For a hardened deployment, regenerate a private pool with
// `supervpn-server reality-genpool N`, set it in [reality].private_keys, and ship
// the matching client build. Inner supervpn password auth always protects VPN
// access regardless.
//
// This file is generated; edit via reality-genpool rather than by hand.
var defaultRealityPrivatePool = []string{
	"z+J7Fs58ROfXxf4NGqabpk+hLvWPe7/g17V6FO8zw5I=",
	"Z1Hs3ZQJOFW4YR2iL1C2wdGjgqmLdlCE9zB40tverLE=",
	"CdXKJDKrmfSMyZBcH9X0pbsu9CpArWZTQqeJPNsuxHE=",
	"iF2Xeuhe7sAbBVITP2dCoJ8g0Fbd+g6BNg7U4BUppB4=",
	"WoZXEg3iZsfKTvqic9BH8Bxzix5Vkyqmi/rzBFgwFEA=",
	"hfNt7gJ6mM0EW2XXv1mbbpT/gwJqodUEGz1LD1ndyyk=",
	"Ac7hIXOte+thNuzP9w29+VACRrDPNxtqR7gRzzjhK4U=",
	"PpIm2/WE8Slr8BvAVUneHUoOVhYBrG67wXw04Kyh9gM=",
	"bDD+1NuLOPEoOab/UygURGz5nTjYnEIlOY81JamL3M4=",
	"pyAjKpM8yyx4K1olRUJ/JXMd+ByjgHFIhNzrVJgvdHs=",
	"jX00ahajwNyD5AfcWR4mimHzaJVT8sAHTw3SNA7NAqQ=",
	"em66O0LN9Le8Bc8dJY6py4DUr6AZE3emf1ELLHNo2ko=",
	"QD+w8oiz82j4d5XsKiu9mADAfhZtaqvGcobxQdxk5fg=",
	"i9HszUfNryQe0m7GE1wP4lHlhblMwAyK0mzvQZ8SNvw=",
	"FyhWDaQbuOPRJCaSQGKMlEuagiblH+VyLKfkFad4dwo=",
	"TEvDQ5x4cxWA/B4I7IMO/TUxFcLYyc+y3erc7+O5mMY=",
	"quGwWSzCTSqC3OQks3Lj8udcmcKZ2BxmBnjUQPIe9AM=",
	"v/rXb7bkbjey/leiGgHmdA/G4ZnbquPz59vSu05nuso=",
	"hD9f59Uzs56oGngOc3dXVsg8b/Fj12NQ816iLCOeIwY=",
	"gaKIL85bsNBnGjckNWu4+eIoWrlAuoi9pjsaxgDCBS0=",
	"33kiB7dNiYGUXnQ+4YK1RGyFF84/nzolfbMO3qfNb84=",
	"FD+sPEfK0E3fPE002g16isfqWxs1y1fpcvAiSEMhtSI=",
	"PJSUOGIXkJ1LXrII9lssLHyCIeBj8EDvz2TuAHl3Jkk=",
	"lSoMgPxCIvyho3xQbi7qo/Wb+xdl4iEo7vcHa6HYyI8=",
	"vNHyV6p7RoMylNQT4tDjB9+duUODiL/m2LzhYroG7q8=",
	"27W+6bVImmsUanU7eWlR41l3JHwMh0jN9tTEZBW4olA=",
	"XGEgCJ4qJWiZH7RfP4Xncu/tR4pZZqnoptw/0R5CtpY=",
	"IYWXOs0Iw893wscFsLsgiJHuRNruxtTBMf7zS3fwVug=",
	"vHdFjHZCw4tIK/UNo5/Sb4kvcd6jkh1Xqtl1D8C4i0s=",
	"sgkOPZqXt3CP2p1dtGFA1Y8CFqHTqcmx456IyYwGAEw=",
	"+wXVZ5povZ52NYgdEMkREWxoqS4rCQcNOWok88PmdiE=",
	"0hHYB1dIPkGgMEhp5NkrQ+ebtmcAG+d5L5m8oRO+sOo=",
	"HVjrzAaFlBcnDLmE5zMGOpUBqnSGzMYaWq5NpsluH+4=",
	"tlEIKNbVlWLPecHYKRNdXBNpcdO/7L2rbyR5tw5hjaI=",
	"22wBMFGnZoqzmvcg4g7yklQzN29Xd+e+3TYda8Wvsio=",
	"swOcFCWwBvazKwEo7yi1Kbawgo6pszX30D/JQigk9Ng=",
	"oTTmDq+Vs8xPFJgs7KsrXrOM3sGCSplQ3uJXV4cWGsc=",
	"SG5hwzffBRs0XGDuy2dXhceN2z18GFRd3LsLgF1zZC0=",
	"OEMwHRHr1l/FJJWI2havjfmeB/J1WLim4AQsbSJlQwY=",
	"5PcTaN9sG7LFt4Nxp8O5ICN5oULgf0ICJA3J4KeHiMk=",
	"RbOrHLGacpmD4uIkOjW3keHBpERAHJY8yBVdhpUjNdI=",
	"+5t6xYzfIPzu3DXpYgTqKuhD+U3Gyo/UwrERfHzZlvo=",
	"OQSDF0RFwliRIYuFi2tTbmKlOwoHKSPsRdZul56V9d8=",
	"etvurjELadDC1IKp+LTeyAJZvJ0Anq2iwbmij/qSMYI=",
	"RHXbo/n0LRNMEWSmhRASdmq2Du9G4l+a0JFZ6KHwfCI=",
	"acAuZEKbqkhiAU/sHnulGwWbl53ZKWiD6fs3xJDp4QQ=",
	"5MAD9Ys9FTFNOZr6tLq/dU3xjoR8haMyHf/2mla6Gss=",
	"AkXl8+MDRQp+DuFdU3iu//i3LPeEHhXOS6pmATQaBNE=",
	"zPvqBbqawWjhwpMVvYvOhsDIE1irtzTM1lYhD8irU8A=",
	"rwUeV41hmeNwO6TiJc9w41WY+/rwJipDf7TaxMbqgOg=",
	"po0EFgsZrfdFs8kiXpGayP++QleWnyaL1sy/TqH0lZw=",
	"ybCK+vwPGWgZYpO1o8DEmRelgwx645hV7holYvRnj8M=",
	"/A5NAwGtOH+7huF3NX2KvlIDeVeIC210PCRmLcr/HY0=",
	"hBDOYgUwKVIivmZFrxgC2CUd4cS9OoOiQz9e1UxJvbQ=",
	"8LaeYaRZuAgBND7HeA+KaIUO8Nl7E+8XEPaCGu8ZgVg=",
	"HxDngiW05e/u5Nsx65vrSTdLhCp7783UiCN4FIweFKo=",
	"fdEhWOk+kbTlP2PIJ4A7cHMar0sG0vr/lL3nE6TYqJ4=",
	"hCerRjnLCvbcJ0SUxXwePyMbYVE9miMzIsqvHlHNTPw=",
	"7nf89E6plEFTxJTSUrwvxDbJMZ83aRHjcNsadB1QEyk=",
	"pHwKa56l1nvwWl9BuVSLF6t15oIwzbKZsS0cK26X+uE=",
	"A5u0dDwjE6oN1HN6+T8cZKt3xhP6qD+nal2LEHAHyOg=",
	"N9Jb+jw8LYxjycMsaJRzbTiWufFzsOenYn6A+J22+xI=",
	"BDZBNImrWnbv7tBSxbPSIu8RHqKshQvW+jvvCeM32hM=",
	"5T6Lmi4WvlYMGvViYfy6GMaygTjkqgq9kkJeO9jpMIE=",
}
