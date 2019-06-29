# Table of contents
- [Executive Summary](#executive-summary)
- [Introduction](#introduction)
- [What is DANE?](#what-is-dane)
- [Why use DANE for SMTP?](#why-use-dane-for-smtp)
- [DANE TLSA records for SMTP](#dane-tlsa-records-for-smtp)
- [Reliable certificate rollover](#reliable-certificate-rollover)
- [Tips, tricks and notices for implementation](#tips--tricks-and-notices-for-implementation)
- [Outbound e-mail traffic (DNS records)](#outbound-e-mail-traffic--dns-records-)
  * [Generating DANE records](#generating-dane-records)
  * [Publishing DANE records](#publishing-dane-records)
  * [Generating DANE roll-over records](#generating-dane-roll-over-records)
  * [Publishing DANE roll-over records](#publishing-dane-roll-over-records)
- [Implementing DANE for SMTP on Postfix (inbound e-mail traffic)](#implementing-dane-for-smtp-on-postfix--inbound-e-mail-traffic-)
  * [Configuring Postfix](#configuring-postfix)
- [Implementing DANE for SMTP on Exim (inbound & outbound e-mail traffic)](#implementing-dane-for-smtp-on-exim--inbound---outbound-e-mail-traffic-)
  * [Configuration for inbound e-mail traffic](#configuration-for-inbound-e-mail-traffic)
    + [Install or generate key pair](#install-or-generate-key-pair)
    + [Configure TLS](#configure-tls)
  * [Configuration for outbound e-mail traffic](#configuration-for-outbound-e-mail-traffic)
    + [DNSSEC validating resolvers](#dnssec-validating-resolvers)
    + [Configure DNSSEC validation in Exim](#configure-dnssec-validation-in-exim)
    + [Configure DANE](#configure-dane)
- [Implementing DANE for SMTP using Halon (inbound & outbound e-mail traffic)](#implementing-dane-for-smtp-using-halon--inbound---outbound-e-mail-traffic-)

<small><i><a href='http://ecotrust-canada.github.io/markdown-toc/'>Table of contents generated with markdown-toc</a></i></small>

# Executive Summary
* DANE is a best-practice technology for securing the transfer of email (SMTP) between organizations across the public Internet.
* Successful DANE deployments require additional operational discipline.
    - Automated monitoring of your own email servers and related DNS records is is a must.
    - Robust automation of coördinated DNS and email server certificate chain updates.
    - These topics will be covered in more detail below.
* Please deploy DANE for your email servers, but plan carefully, botched deployments not not only harm the domain in question, but also have a deterrent effect on adoption by others.

# Introduction
This how-to is created by the Dutch Internet Standards Platform (the organization behind [internet.nl](https://internet.nl)) and is meant to provide practical information and guidance on implementing DANE for SMTP.

# What is DANE?
DANE is short for "**D**NS-based **A**uthentication of **N**amed **E**ntities" and is described in [RFC 6698](https://tools.ietf.org/html/rfc6698) and [RFC 7671](https://tools.ietf.org/html/rfc7671). DANE enables publication in secure DNS of keys and certificates for use with TLS. DANE TLSA records published in the server operator's signed DNS zone provide a downgrade-resistant means to discover support for STARTTLS and to validate the server's certificate chain without relying on additional trusted parties outside the delegation chain in DNS.

DANE is designed to work with any TLS service, not just email, but DANE for HTTP is not presently supported by the major browsers and so has seen little deployment. DANE for SMTP (which is described in [RFC 7672](https://tools.ietf.org/html/rfc7672) on the other hand, is used increasingly and adds active attack (man-in-the-middle) resistance to SMTP transport encryption [RFC 7672 Section 1.3](https://tools.ietf.org/rfc7672#section-1.3). DANE for SMTP uses the presence of DANE TLSA records to securely signal TLS support and to publish the means by which SMTP clients can successfully authenticate legitimate SMTP servers. The result is called "opportunistic DANE TLS", and resists downgrade and man-in-the-middle (MITM) attacks when the destination domain and its MX hosts are DNSSEC signed, and TLSA records are published for each MX host.

# Why use DANE for SMTP?
The use of opportunistic TLS (via STARTTLS) is not without risks:
* Because forcing the use of TLS for all mail servers would break backwards compatibility, SMTP uses opportunistic TLS (via STARTTLS) as a mechanism to enable secure transport between mail servers. However, the fact that STARTTLS is opportunistic means that the initial connection from one mail server to another always starts unencrypted making it vulnerable to man in the middle attacks. If a mail server does not offer the 'STARTTLS capability' during the SMTP handshake (because it was stripped by an attacker), transport of mail occurs over an unencrypted connection. 
* By default mail servers do not validate the authenticity of another mail server's certificate; any random certificate is accepted (see [RFC 3207](https://tools.ietf.org/html/rfc3207)).
    - It was unclear which CAs to trust when validating the certificate for a given destination.
    - In MTA-to-MTA SMTP, server hostnames for the destination domain are obtained indirectly via DNS MX loookups, but, without DNSSEC, these names cannot be trusted.  As a result, it was unclear which names to verify in the certificate.
* As as result, even when STARTTLS is used, a man in the middle attacker can intercept the traffic with any certificate of his choice.

DANE addresses these shortcomings because:
* The operator of the receiving mail server is obligated to ensure that any published TLSA records at all times match the server's certificate chain, and that STARTTLS is enabled and working.
* This allows sending mail servers to unconditionally require STARTTLS with a matching certificate chain. Otherwise, the sending mail server aborts the connection and tries another server or defers the message.
* Receiving servers with published TLSA records, are therefore no longer vulnerable to "STARTTLS stripping".

# DANE TLSA records for SMTP
As specified in [Section 2 of RFC6698](https://tools.ietf.org/html/rfc6698#section-2), a DANE TLSA record is used to associate a TLS server certificate or public key with a network service endpoint, thus forming a "TLSA certificate association".  For MTA-to-MTA SMTP the TLSA record is published in DNS at a domain which is formed by prepending `_25._tcp.` to the hostname of each SMTP server (or sometimes its full __secure__ CNAME expansion). For example (all records assumed DNSSEC signed, associated RRSIG not shown):
```
example.com. IN MX 0 mx1.example.com.
example.com. IN MX 0 mx2.example.com.
;
mx1.example.com. IN A 192.0.2.1
_25._tcp.mx1.example.com. IN TLSA 3 1 1 ab837de5bfde4288617983905e8e15398d0b4d32152399c816bba122b7bb0990
_25._tcp.mx1.example.com. IN TLSA 3 1 1 844feb66064906f0f2079f2adc8ce0457829ebc9d7a57527bc1bbf686683f8b2
;
mx2.example.com. IN A 192.0.2.1
_25._tcp.mx2.example.com. IN TLSA 3 1 1 abe4387121ba18ea82e7f148366e0e3bd55d72ab6bc9abb6c96b8bedfede3c48
_25._tcp.mx2.example.com. IN TLSA 3 1 1 dfc2908e0a2331eeeb11f2028cb2b265cdde6045d9264095854fb006b5de0a8f
```
The four fields of a TLSA record are:
* **Certificate Usage** ([Section 2.1.1 of RFC6698](https://tools.ietf.org/html/rfc6698#section-2.1.1)), with values as follows:
    - **3** or **DANE-EE** ([Section 2.1 of RFC7218](https://tools.ietf.org/html/rfc7218#section-2.1)), or DANE-EE(3).  This is an end-entity "certificate association", i.e. it specifies the actual service certificate or public key, rather than a trusted issuer. When in doubt, use this certificate usage.
    - **2**, or **DANE-TA** ([Section 2.1 of RFC7218](https://tools.ietf.org/html/rfc7218#section-2.1)),
      or DANE-TA(2). This is a trust-anchor "certificate association", i.e. it designates a CA as
      trusted to issue certificates for the (in this case SMTP) service.
    - Certificate usages PKIX-EE(1) and PKIX-TA(0) are not applicable to MTA-to-MTA SMTP. See [Section 3.1.2 of RFC7672](https://tools.ietf.org/html/rfc7672#section-3.1.3)
* **Selector** ([Section 2.1.2 of RFC6698](https://tools.ietf.org/html/rfc6698#section-2.1.2)), with values as follows:
    - **1**, or **SPKI** ([Section 2.2 of RFC7218](https://tools.ietf.org/html/rfc7218#section-2.2)), or SPKI(1). This indicates that the __certificate association data__ field (see below) matches just the subject public key of the certificate (end-entity or trust-anchor per the __usage__). When in doubt, use this selector.
    - **0**, or **Cert** ([Section 2.2 of RFC7218](https://tools.ietf.org/html/rfc7218#section-2.2)), or Cert(0). This indicates that the __certificate association data__ field (see below) matches the complete certificate.
* **Matching type** ([Section 2.1.3 of RFC6698](https://tools.ietf.org/html/rfc6698#section-2.1.3)), with values as follows:
    - **1**, or **SHA2-256** ([Section 2.3 of RFC7218](https://tools.ietf.org/html/rfc7218#section-2.3)), or SHA2-256(1). This indicates that the __certificate association data__ field (see below) is the SHA2-256 digest of the DER encoding of the public key (selector SPKI(1)) or the certificate (selector Cert(0)). When in doubt, use this matching type.
    - **2**, or **SHA2-512** ([Section 2.3 of RFC7218](https://tools.ietf.org/html/rfc7218#section-2.3)), or SHA2-512(2). This indicates that the __certificate association data__ field (see below) is the SHA2-512 digest of the DER encoding of the public key (selector SPKI(1)) or the certificate (selector Cert(0)). The practical security advantages of SHA2-512 over SHA2-256 are slim, and increased DNS packet sizes make this choice less preferred.
    - **0**, or **Full** ([Section 2.3 of RFC7218](https://tools.ietf.org/html/rfc7218#section-2.3)), or Full(0). This indicates that the __certificate association data__ field (see below) contains the complete DER encoding of the public key (selector SPKI(1)) or the certificate (selector Cert(0)). This leads to even larger packet sizes, especially with RSA keys or full certificates. This matching type should be avoided.
* **Certificate association data** ([Section 2.1.4 of RFC6698](https://tools.ietf.org/html/rfc6698#section-2.1.4)):
   - This field holds the either the digest value or full DER value of the public key (SPKI(1)) or certificate (Cert(0)). It is written in hexadecimal (presentation form) in zone files and user interfaces, and carried as raw binary data (wire form) in DNS packets.

Consequently, for MTA-to-MTA SMTP, you can keep it simple and only use or both of two TLSA RR types, none of the others offer any advantages:

* **3 1 1**, or **DANE-EE(3) SPKI(1) SHA2-256(1)**. These encode the SHA2-256 digest of an SMTP-server's public key.
* **2 1 1**, or **DANE-TA(2) SPKI(1) SHA2-256(1)**. These encode the SHA2-256 digest of a trusted issuer CA's public key.

The [certificate rollover](#reliable-certificate-rollover) strategies below use only these record types.

When multiple TLSA records are published for the same service,
authentication succeeds when **any** one of them is a match.  As
we'll see below, having a mixture of matching and non-matching keys
facilitates non-disruptive certificate changes.

Use of DANE-TA(2) trust-anchors does not imply the use of one of
the WebPKI public CAs. A domain can use its own private CA to issue
server certificates, provided that there's no requirement to also
support WebPKI-based server authentication (e.g. MTA-STS).  While
some sites do use DANE-TA(2) trust-anchors associated with public
CAs such as "Let's Encrypt", this convenience comes at a cost to
security, since __domain-validated__ certificate issuance uses
comparatively weak __proofs__ of domain control. "3 1 1" records
offer stronger security.

Some servers are configured with multiple certificate chains even
for the same hostname (not to be confused with SNI-based
single-certificate **per-hostname**). Such a server might, for
example, have one certificate chain with an RSA key (for interoperability
with legacy systems), and one or more additional certificate chains
with perhaps an ECDSA or an Ed25519 key. Such servers may present
different certificates to different clients based on the client's
advertised supported algorithms. This means that the server's TLSA
records need to match all the possible certificates any client may
encounter. Such a server would need DANE-EE(3) TLSA records, one
per algorithm, and then additional per-algorithm TLSA records during
certificate updates. This is an advanced configuration, and most
operators should deploy just one certificate chain at a time.

# Reliable certificate rollover
It is a good practice to replace certificates and keys from time to time, but this need not and should not disrupt email delivery even briefly.
* Since a single TLSA record is tied to a particular certificate or (public) key, the TLSA records that match a server's certificate chain also change from time to time.
* Because TLSA records are cached by DNS clients, the TLSA records that match a new certificate chain need to be published some time prior to its deployment.
* But then the new TLSA records will be seen by some clients before the corresponding certificates are in place.
* An outage is avoided by publishing **two** sets of TLSA records:
    - Legacy TLSA records that continue to match the old certificate chain until it is replaced.
    - Fresh TLSA records that will match the new new certificate chain once it is deployed.
* Both are published together long enough to ensure that nobody should still caching only the legacy records. 
* When the new certificate chain is deployed, tested and if all is well, the legacy TLSA records are dropped.

Two ways of handling certificate rollover are known to work well, in combination with automated monitoring to ensure that the TLSA records and certificates are always current and correct.

1. **Current + next**. This roll-over scheme always publishes two TLSA records per server certificate.
    - One with the SHA2-256 fingerprint of the mail server's current public key (a "3 1 1" record).
    - And a second with the SHA2-256 fingerprint of the mail server's next public key (also a "3 1 1" record).
2. **Current + issuer**. This roll-over scheme always publishes two TLSA records per mail server certificate.
    - One with the SHA2-256 fingerprint of the mail server's current public key (3 1 1)
    - And a second with the SHA2-256 fingerprint of the public key of an issuing CA that directly or indirectly signed the server certificate (2 1 1). This need not be (and typically is not) a root CA.

## Current + next details
With the "current + next" approach, because both fingerprint are **key** fingerprints, the "next" TLSA record can be generated and published in advance of obtaining the corresponding certificate. In particular, if keys are rotated often enough (every 30 to 90 days or so), the next key can be generated as soon-as the previous key and certificate are deployed. This allows plenty of time to publish the corresponding **next** "3 1 1" TLSA record to replace the legacy record for the decommissioned key.

With TLSA record that will match the next key long in place, when it is time to deploy that key with a new certificate some 30 to 90 days later, a new certificate is obtained for *that* key and deployed, and the process begins again with another "next" key generated right away.

Deployment of a new certificate and key must be predicated (automated check) on the corresponding TLSA "3 1 1" record being in place for some time, not only on the primary DNS nameserver, but also on all secondary nameservers. Explicit queries against all the servers are to check for this are highly recommended.

Some servers have keys and certificates for multiple public key algorithms (e.g. both RSA and ECDSA). In that case, not all clients will negotiate the same algorithm and see the same key. This means that a single "3 1 1" record cannot match the server's currently deployed certificate chains. Consequently, for such servers the "3 1 1" current + "3 1 1" next TlSA records need to be provisioned separately for each algorithm. Failure to do that can result in hard to debug connectivity problems with some sending systems and not others.

Use of the same key (and perhaps wildcard certificate) across all of a domain's SMTP servers (all MX hosts) is **not** recommended. Such keys and certificates tend to be rotated across all the servers at the same time, and any deployment mistakes then lead to an outage of inbound email. Large sites with proper monitoring and carefully designed and automated rollover processes can make wildcard certificates work, but if in doubt, don't overestimate your team's ability to execute this flawlessly.

When monitoring your systems, test every IPv4 and IPv6 address of each MX host, not all clients will be able connect to every address, and none should encounter incorrect TLSA records, neglected certificates, or even non-working STARTTLS. Also test each public key algorithm, or stick to just one. All DANE-capable SMTP servers support both RSA and ECDSA P-256, so you can pick just RSA (2048-bit key) or ECDSA (P-256).

Make sure that your servers support TLS 1.2, and offer STARTTLS to all clients, even those that have not sent you email in the past. Denying STARTTLS to clients with no IP "reputation" would lock them out indefinitely if they support DANE, since they then can never send any initial mail in the clear to establish their reputation.

## Current + issuer details
With the "current + issuer" approach, the published TLSA records specify the public keys of the leaf (end-entity), the second can be known in advance of obtaining the corresponding certificate. In particular, if keys are rotated often enough (every 30 to 90 days or so), the next key can be pre-generated as soon-as the previous key and certificate are deployed. This allows plenty of time to publish the corresponding **next** "3 1 1" TLSA record to replace the legacy record for the decommissioned key.

# Tips, tricks and notices for implementation
This section describes several pionts for attention when implementing DANE for SMTP. 

* Purchasing of expensive certificates for mail server has no to little added value for the confidentiality since mail server don't validate certificates by default. Depending on the context there can be other advantages which makes organizations decide to use specific certificates.
* It is recommended to use a certificates public key for generating a TLSA signature (selector type "1") instead of the full certificate (selector type "0"), because this enables the reuse of key materials. Notice that the use of Forward Secrecy decreases the need to use a new key-pair on every occasion. 
* An issuer certificate (usage type "2") validates only when the full certificate chain is offered by the receiving mail server. 
* Mail servers don't validate certificates and therefore don't have their own certificate store. That's why DANE for SMTP only supports usage type "2" (DANE-TA) and usage type "3" (DANE-EE). Usage type "0" (PKIX-TA) and usage type "1" (PKIX-EE) are not supported. 
* Make sure the TTL (time-to-live) of your TLSA records is not too high. This makes it possible to apply changes relatively fast in case of problems. A TTL between 30 minutes (1800) and 1 hour (3600) is recommended.
* The refresh value of your full DNS zone should be in accordance with the TTL setting of your TLSA record, to make sure all name servers give the same information when (after expiration of the TLSA TTL) being queried.
* In case of roll-over scheme "current + issuer", the use of the root certificate is preferred because in some contexts ([PKIoverheid](https://en.wikipedia.org/wiki/PKIoverheid)) this makes it easier to switch supplier / certficate without impacting DANE. (Remember [DigiNotar](https://en.wikipedia.org/wiki/DigiNotar)). 
* Roll-over scheme "current + next" gives less flexibility but the highest form of certainty, because of "tight pinning".
* Implement monitoring of your DANE records to be able to detect problems as soon as possible. 
* Make sure your implementation supports the usage of a CNAME in your MX record. There are some inconsistencies between multiple RFC's. According to [RFC 2181](https://tools.ietf.org/html/rfc2181#section-10.3) a CNAME in MX records is not allowed, while [RFC 7671](https://tools.ietf.org/html/rfc7671#section-7) and [RFC 5321](https://tools.ietf.org/html/rfc5321#section-5.1) imply that the usage of a CNAME in MX records is allowed.

# Outbound e-mail traffic (DNS records)
This part of the how-to describes the steps that should be taken with regard to your outbound e-mail traffic. This enables other parties to use DANE for validating the certificates offered by your e-mail servers. 

## Generating DANE records
**Primary mail server (mail1.example.com)**

Generate the DANE SHA-256 hash with the following command:

`openssl x509 -in /path/to/primary-mailserver.crt -noout -pubkey | openssl pkey -pubin -outform DER | openssl sha256`

This command results in the following output:
 
> (stdin)= 29c8601cb562d00aa7190003b5c17e61a93dcbed3f61fd2f86bd35fbb461d084

**Secondary mail server (mail2.example.com)**

For the secondary mail server we generate the DANE SHA-256 hash using the command:

`openssl x509 -in /path/to/secondary-mailserver.crt -noout -pubkey | openssl pkey -pubin -outform DER | openssl sha256`

This command results in the following output: 
> (stdin)= 22c635348256dc53a2ba6efe56abfbe2f0ae70be2238a53472fef5064d9cf437

## Publishing DANE records
Now that we have the SHA-256 hashes, we can construct the DNS records. We make the following configuration choices:
* Usage field is "**3**"; we generated a DANE hash of the leaf certificate itself (DANE-EE: Domain Issued Certificate).
* Selector field is "**1**"; we used the certificates' public key to generate DANE hash/signature.
* Matching-type field is "**1**"; we use SHA-256.

With this information we can create the DNS record for DANE:

> _25._tcp.mail.example.com. IN TLSA 3 1 1 29c8601cb562d00aa7190003b5c17e61a93dcbed3f61fd2f86bd35fbb461d084  
> _25._tcp.mail2.example.com. IN TLSA 3 1 1 22c635348256dc53a2ba6efe56abfbe2f0ae70be2238a53472fef5064d9cf437

## Generating DANE roll-over records
We use the provided bundle file for generating the DANE hashes belonging to the root certificate. In order to do that, we first split the bundle file into multiple certificates using `cat ca-bundle-file.crt | awk 'BEGIN {c=0;} /BEGIN CERT/{c++} { print > "bundlecert." c ".crt"}'`. In this specific case this results in two files: _bundlecert.1.crt_ and _bundlecert.2.crt_.

For each file we view the **subject** and the **issuer**. We start with the first file using the following command:

`openssl x509 -in bundlecert.1.crt -noout -subject -issuer`

This results in the following output:

> subject=C = GB, ST = Greater Manchester, L = Salford, O = Sectigo Limited, CN = Sectigo RSA Domain Validation Secure Server CA  
> issuer=C = US, ST = New Jersey, L = Jersey City, O = The USERTRUST Network, CN = USERTrust RSA Certification Authority

For the second file we use the command:

`openssl x509 -in bundlecert.2.crt -noout -subject -issuer`

This results in the following output:
> subject=C = US, ST = New Jersey, L = Jersey City, O = The USERTRUST Network, CN = USERTrust RSA Certification Authority  
> issuer=C = US, ST = New Jersey, L = Jersey City, O = The USERTRUST Network, CN = USERTrust RSA Certification Authority

Based on the information of these two certificates, we can conclude that the second certificate (bundlecert.2.crt) is the root certificate; since root certificates are self-signed the **subject** and the **issuer** are the same. The other certificate (bundlecert.1.crt) is an intermediate certificate which is (in this case) signed by the root certificate. 

## Publishing DANE roll-over records
Because we prefer the root certificate to be our roll-over anchor, we generate the DANE SHA-256 hash using the command:

`openssl x509 -in bundlecert.2.crt -noout -pubkey | openssl pkey -pubin -outform DER | openssl sha256`

This results in the following output:

> (stdin)= c784333d20bcd742b9fdc3236f4e509b8937070e73067e254dd3bf9c45bf4dde

Since both certificates for the primary and secondary come from the same Certificate Authority, they both have the same root certificate. So we don't have to repeat this with a different bundle file.

Now that we have the SHA-256 hash, we can construct the DANE roll-over DNS records. We make the following configuration choices:
* Usage field is "**2**"; we generated a DANE hash of the root certificate which is in the chain the chain of trust of the actual leaf certificate (DANE-TA: Trust Anchor Assertion). 
* Selector field is "**1**"; because we use the root certificate's public key to generate a DANE hash.
* Matching-type field is "**1**"; because we use SHA-256.

With this information we can create a rollover DNS record for DANE:
> _25._tcp.mail.example.com. IN TLSA 2 1 1 c784333d20bcd742b9fdc3236f4e509b8937070e73067e254dd3bf9c45bf4dde  
> _25._tcp.mail2.example.com. IN TLSA 2 1 1 c784333d20bcd742b9fdc3236f4e509b8937070e73067e254dd3bf9c45bf4dde

# Implementing DANE for SMTP on Postfix (inbound e-mail traffic)

**Specifics for this setup**
* Linux Debian 9.8 (Stretch) 
* SpamAssassin version 3.4.2 (running on Perl version 5.28.1)
* Postfix 3.4.5
* BIND 9.10.3-P4-Debian
* Two certificates (for two mail servers) from Comodo / Sectigo

**Assumptions**
* DNSSEC is used
* Mail server is operational
* Software packages are already installed

## Configuring Postfix
Postfix plays an important role in using DANE for validating the when available.

Make sure the following entries are present in **/etc/postfix/main.cf**

`smtp_dns_support_level = dnssec`  

This setting tells Postfix to perform DNS lookups using DNSSEC. This is an important prerequisite for DANE to be effective, since regular DNS lookups can be manipulated. Without DNSSEC support, Postfix cannot use DANE.

`smtp_tls_security_level = dane`  

By default Postfix uses opportunistic TLS (smtp_tls_security_level = may) which is susceptible to man in the middle attacks. You could tell Postfix to use mandatory TLS (smtp_tls_security_level = encrypt) but this breaks backwards compatibility with mail servers that don't support TLS (and only work with plaintext delivery). However, when Postfix is configured to use the "dane" security level (smtp_tls_security_level = dane) it becomes resistant to man in the middle attacks, since Postfix will connect to other mail servers using "mandatory TLS" when TLSA records are found. If TLSA records are found but are unusable, Postfix won't fallback to plaintext or unauthenticated delivery. 

`smtp_host_lookup = dns`  

This tells Postfix to perform lookups using DNS. Although this is default behavior it is important to make sure this is configured, since DANE won't be enabled if lookups are performed using a different mechanism.

`smtpd_tls_CAfile = /path/to/ca-bundle-file.crt`  

When applying a DANE roll-over scheme using an "issuer certificate" (an intermediate or root certificate), Postfix must be able to provide the certificates of the used issuer in the chain of trust. Hence this setting.

# Implementing DANE for SMTP on Exim (inbound & outbound e-mail traffic)
**Specifics for this setup**
* Ubuntu 18.10 ‘Cosmic Cuttlefish’ 
* Exim 4.92 (DANE support is non-experimental since version 4.91)

**Assumptions**
* DNSSEC is used
* Mail server is operational

## Configuration for inbound e-mail traffic

### Install or generate key pair
You can use a commercial or Let's Encrypt certificate, but you can also generate your own key pair by using the provided Exim tools. Use the following command to generate a key pair.

`sudo bash /usr/share/doc/exim4-base/examples/exim-gencert`

### Configure TLS 
In Exim you should configure TLS by adding the following to **main/03_exim4-config_tlsoptions**

    MAIN_TLS_ENABLE = yes
    tls_advertise_hosts = *
    tls_certificate = /path/to/certificate.crt
    tls_privatekey = /path/to/private.key

## Configuration for outbound e-mail traffic
This part of the how-to describes the steps that should be taken with regard to your outbound e-mail traffic. This enables other parties to use DANE for validating the certificates offered by your e-mail servers. 

### DNSSEC validating resolvers
Make sure to configure DNSSEC validating resolvers on the mail server. When using the locale systemd resolver, make sure to add the following to **/etc/systemd/resolved.conf**.

`DNSSEC = yes`

### Configure DNSSEC validation in Exim
In Exim you explicitly need to configure DNSSEC validation by adding the following to **main/02_exim4-config_options** since some resolvers only validate DNSSEC on request. 

`dns_dnssec_ok = 1`

### Configure DANE
In order to use DANE, you should tell Exim to check for DANE records when sending e-mail. You can configure DANE validation to be mandatory by adding the following to **transport/30_exim4-config_remote_smtp**. 

`hosts_require_dane = *`

This means that TLS connections are not accepted when the domain you are trying to send mail to does not have a valid TLSA record. Since this is rather strict and not recommended to be the default, you are probably better of by configuring DANE validation to be additional. This can be done by adding the following to **transport/30_exim4-config_remote_smtp**.

`hosts_try_dane = *`

Notice that depending on the way you configured Exim, you need to apply DANE for all [SMTP transports](https://www.exim.org/exim-html-current/doc/html/spec_html/ch-how_exim_receives_and_delivers_mail.html#SECTprocaddress).

# Implementing DANE for SMTP using Halon (inbound & outbound e-mail traffic)
Serveral Dutch hosting providers use Halon (a scriptable SMTP server who's virtual appliances are based on FreeBSD) as the internet facing e-mail server. The actual mail boxes reside on Direct Admin (which uses Exim) within the internal network. In this specific setup you could say that all security features are applied at the internet facing mail server which is Halon. 

Halon has built-in support for DANE and can be configured by using the information provided on the website: [https://halon.io/dane](https://halon.io/dane) and [https://wiki.halon.io/DANE](https://wiki.halon.io/DANE).
