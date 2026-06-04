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
	"6BzA4xuxNPKUSrB+czKXR25E+oCMJx/IYCREBoHfh3U=",
	"cOjKy8jFCBCRgVcB0Z+3AJKHR4M22+G4lHKLwreDfl4=",
	"Lyoktg8p0lkK9Yn915DVevcdk0zGJsKyeJdZbk2pS2k=",
	"mvpyK/nk0a/H6TlAoC6E090u39NkBjHK+eag4e2EkkY=",
	"IvyyuZjdIIZaWUA4NK79pfMY609lLKchtmq6lKJKK2E=",
	"rCrQzrm1by5hXN0mRnOeiyI2QiGiKp/WDr+FWl/3CSg=",
	"1TzKBgWyfgNodBAQBX4H3aKpMH1OVFxmKvn/wLqrN1w=",
	"B4Vc+MSVdO4xVx6/fe0oVSziJITkNXlZTcc0pDJ7MDc=",
	"F3dxhyQBv4U6KISZfFBCczi6WP0A2nHTcDwpKfkZAF4=",
	"+zQUznEpy4RDBRRT8idw52z4m8B4eSlpbR48zAiCny4=",
	"IDds/BFsg86DHEjsYuNAd1VAUGu8QsDjg/tPOuj1JFE=",
	"ocNPa1FzW9iFpw3g3HBZjlnqoIptRNgv61VuoqjTKlM=",
	"nMiPJtxRj/T1yrjkPZu4zehKgh0GYiQAixkZM/853zk=",
	"i8PzIJ+AKdkkBZRyavRuQxAPKJ8WtMdUzmjRR43WZ3I=",
	"ahtUZ52TN5ATvYXpho2i0gUbcwSB4bSyQWYJNfDcp10=",
	"sbP5w2iEzLmNjVupYt/oH4KMdeFd7hyn6/p8QYtDBls=",
	"3Zgr1nfnF+5uOYEG1OVLGcMj/4HgbDj1w/IgsX2n1Ts=",
	"gczKrE2G9blrReDN27SAM5Gs8d2U/+lRS2gQYUqbjF0=",
	"bXMwYYU/dK055Z9Oqp0UpqaYQRdufejJrHZ9juNHIzU=",
	"P6uvqZdF70VJY+tAIxxxMjYCAA4UGD8EZIcOnVOmJyE=",
	"w4v6GrusqbXMR9LdC2qvAiXZYc2T+AAnyVUx9Hu2kxQ=",
	"sK+uAWhDrX8aG8UzYDJjD0M1KV74ECnaBIQwmjqiIz0=",
	"cLrUs92iIGs2TgCtfKAbwEYEIn5kFuFIrZrl5lcYbAY=",
	"dqLakS4Ukgjkr6MYuSRqCpKydirmRgG4sAnmPZkuFk0=",
	"DTeruSt10MKenmh1hfG/oRauAlsspSqldOViACBeIwQ=",
	"WMzSf8cSJ8zS3fhygYbLL8uGAPmrQe3jdcRa8nwitgc=",
	"d8cPB0Bz+W3P6YzvQLAPPwvUZ3SUwnUDLoCEtBQ1OwY=",
	"bmL0cHGY48lxQZyxEKSKOXyeQJYjBEcRxN0WnhYktyE=",
	"WF+57BzejVzc68fBLPpJbaT/OLQRCfFPIxNqg11H9lE=",
	"JU7ww4VFg+E1XLgNeiAmO058AmrOjK5hbqw7ZZ8WqDs=",
	"kXqshY4F22dxeMgNmA36/4xVAL+ZdTCWX72N/+sPhyY=",
	"kS7ccnjN6okFoeIQ19a6T5ZHArO1eB/8LZlXfneWRxw=",
	"rJJ4/h+ae242do+kzcihFx4wZosdAC01SX0gRFQ1ZCc=",
	"WmXgpI6rcc4CuaeecR+/dWYNaC0NbWZtm4Skvqes+Sc=",
	"NXpGYPMsptvfF3V3uBdAskK49a1OAXae+tbBXC1bBzw=",
	"P5n+IeSWwQr+KIoM0rbp8GuZazEW3EgXx4EP6G7v7i0=",
	"ZIvTLEsJKo3AZ+kW6fXXUJdQhBDlAxWBDs9quB20YUo=",
	"PPHLwfwEHMILLuwjCrzUA+uYHYpOO8j86XWJ03sCfX4=",
	"YI9FQf94aHQI0WJH3eJznwi5cZpFRaZeUSzCM93lgHY=",
	"Wlb9TYP1z1jREUyfM/3izVADWEMEnS7B6GjsMXFcaFI=",
	"q2HPnMj04XetCOvB3++CBQwxYYmxzO4am1epZm/sO2c=",
	"ZEB658/N3+IJX+Wk2EE+1TH1OaodsMBIR/1C0o9ivDk=",
	"znoXrgdTuV+3A+1/BQs4zvCit/4kQZz/f1ZjHv3YbVQ=",
	"6tuFlKsweMXC9GPo76BSoX9sfXKm8sp7JAkcetGsaCg=",
	"/bWV/L+Vs577Q5ags6uR7ItOBPRQ6yan9g7X/btT+Bc=",
	"0GdyUqESWaS5LChuK4xFSnMaKxZ3uSr0vkXz6AiRuls=",
	"pfWY4Xb49DnxhIxrFRsbirUa9dFE1mRBUcRGbNKsziI=",
	"H+kIReLDP/9A0xr7m0e8OH+IHKAFY5dOthl9Afcv1FI=",
	"WOEC+UfDwWPMR3riQRcLvjFhUhgi1ngJHlfe+0g7vUM=",
	"mtBISUnUXsGTb3w8tQqMSGrI2n2xV8WBoZI6x3CZmwI=",
	"nZePzYPZm0g+CvnSSz5wLDeTglrwD3JelowDCdg+0y4=",
	"0l0AQkhGVP3v1v1KjZOFyzfXiP6qO8aBpmV1fJ5m0GM=",
	"mfcpWuCHeONkSuawLGNTQPLJ0JL8XX6MtR6l5Bravlc=",
	"ejUuDA/oPw3LaheoiSal14apHOPN+qei2cHI6AJrxG4=",
	"OJ7bxG6XFNOSGxaJ5FCWU9YTljK5xztJKEfHqB3gCGg=",
	"2FUEegO/bBVbHijTfkzGvr0/RqlGckxJSwkruLLPIEw=",
	"8LKPtTBMbmglGLPe+F66ZWa1tS4tDyhfO3tLjKW6XRU=",
	"yUkczMYxk61RaV0dhXEzK6PyDCknMP6on0lu4ClMbk8=",
	"PuQAjKm8D3sUR3/Kk+HaQ0vZxXZoZ7cdZm1WHRIqs3U=",
	"1Vg/QvLIXInLv58Iivu0XkQWKnxKkMPz3jjgyYtpYC0=",
	"IYgpWPv/4bXb5ssQAYsJn0ZflxCkJz45yIivLUKzPBE=",
	"TUcKf9OyFKYZq/mjjMgufgj61NbRyvMop9F3/JtJOEU=",
	"V50DMLBZ30bRm3D0NVqFIiKySb3D1yZV60cxUN0Q9QY=",
	"sdcL5245dQw348WKDgCokNYrlL0fJu4k9iptUdRMfFw=",
}
