---
title: A CoRIM Profile for Arm's Confidential Computing Architecture (CCA) Endorsements
abbrev: Arm CCA Endorsements
docname: draft-ydb-rats-cca-endorsements-latest
date: {DATE}
category: info
ipr: trust200902
area: Security
workgroup: RATS

stand_alone: yes
pi:

  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  text-list-symbols: -o*+
  docmapping: yes

author:

-
  name: Yogesh Deshpande
  org: Arm Ltd
  email: yogesh.deshpande@arm.com

-
  name: Thomas Fossati
  org: Linaro
  email: thomas.fossati@linaro.org

contributor:
 -  name: Simon Frost
    organization: Arm Limited
    email: Simon.Frost@arm.com
 -  name: Sergei Trofimov
    organization: Arm Limited
    email: Sergei.Trofimov@arm.com

normative:
  I-D.ietf-rats-corim: rats-corim
  I-D.ffm-rats-cca-token: cca-token
  RFC5280: pkix-x509
  RFC7468: pem

informative:
  RFC9334: rats-arch
  CCA-ARCH:
    author:
      org: Arm
    title: Learn the architecture - Introducing Arm Confidential Compute Architecture
    target: https://developer.arm.com/documentation/den0125/0400
    date: 19 March 2025

entity:
  SELF: "RFCthis"

--- abstract

Arm Confidential Computing Architecture (CCA) Endorsements comprise reference values and cryptographic key material that a Verifier needs to appraise Attestation Evidence produced by an Arm CCA system.

This memo defines CCA Endorsements as a profile of the CoRIM data model.

--- middle

# Introduction

Arm Confidential Computing Architecture (CCA) Endorsements comprise reference values and cryptographic key material that a Verifier needs to appraise Attestation Evidence produced by an Arm CCA system {{-cca-token}}.

This memo defines CCA Endorsements as a profile of the CoRIM data model {{-rats-corim}}.

# Conventions and Definitions

{::boilerplate bcp14}

The reader is assumed to be familiar with the terms and concepts introduced in {{-cca-token}} and in {{Section 4 of -rats-arch}}.

# Arm CCA Endorsements
{: #sec-cca-endorsements }

The Arm CCA Attester is a layered Attester comprising separate yet linked Platform and Realm Attesters.
For the details, see {{Section 3 of -cca-token}}.
Appraising Arm CCA Evidence requires Endorsements for both the Platform and Realm.
This document outlines the Platform and Realm Endorsements in {{sec-platform-endorsements}} and {{realm-endorsements}}, respectively.

## Arm CCA Platform Endorsements {#sec-platform-endorsements}

There are two types of CCA Platform Endorsements:

* Reference Values ({{sec-ref-values}}), i.e., measurements of the CCA Platform firmware.
* Attestation Verification Keys ({{sec-keys}}), i.e., cryptographic keys that can be used to verify Evidence produced by the CCA Platform, along with the identifiers that link the keys to their platform instances.

### Arm CCA Platform Endorsement Profile

Arm CCA Platform Endorsements are carried in one or more CoMIDs within a CoRIM.

The profile attribute in the CoRIM MUST be present and MUST be the URI `tag:arm.com,2025:cca_platform#1.0.0`, as shown in {{ex-cca-platform-profile}}.

~~~
{::include examples/platform-profile.diag}
~~~
{: #ex-cca-platform-profile title="CoRIM profile for CCA Platform Endorsements version 1.0.0" }

### Arm CCA Platform Endorsements linkage to CCA Platform {#sec-cca-rot-id}

Each CCA Platform Endorsement, be it a Reference Value or an Attestation Verification Key, is associated with a unique identifier known as CCA Platform Implementation ID (see {{Section 4.4.2 of -cca-token}}).
The Implementation ID uniquely identifies a given implementation of a CCA Platform and it is used by the Endorser or Reference Value Provider as an anchor to which Reference Values and Attestation Verification Keys for a CCA Platform are linked.

To encode an Implementation ID, the `tagged-bytes` variant of the `$class-id-type-choice` is used, as described in {{cddl-impl-id}}.
The length of the byte string MUST be exactly 32.

~~~ cddl
impl-id-tagged-bytes = #6.560(arm-platform-implementation-id-type)

arm-platform-implementation-id-type = bytes .size 32
~~~
{: #cddl-impl-id title="CCA Platform Implementation ID encoding"}

Besides, a CCA Endorsement can be associated with a specific *instance* of a certain CCA Platform implementation - as is the case of Attestation Verification Keys.
The Instance ID (see {{Section 4.4.1 of -cca-token}}) provides a unique identifier for a given CCA Platform instance.

To encode an Instance ID, the `tagged-ueid-type` variant of the `$instance-id-type-choice` is used, as described in {{cddl-inst-id}}.
The first byte MUST be 0x01 (RAND) followed by the 32-byte unique instance identifier.

~~~ cddl
inst-id-tagged-ueid = #6.550(eat-ueid-rand-type)

eat-ueid-rand-type = bytes .join eat-ueid-rand-fmt

eat-ueid-rand-fmt = [
  ; the type byte is 0x01
  ueid-rand-typ
  bytes .size 32
]

ueid-rand-typ = h'01'
~~~
{: #cddl-inst-id title="CCA Platform Instance ID encoding"}

CCA Attestation Verification Keys are associated with a CCA Platform instance by means of the Instance ID and the corresponding Implementation ID.
These identifiers are typically found in the subject of a CoMID triple, encoded in an `environment-map` as shown in {{ex-cca-platform-id}}.

~~~ cbor-diag
{::include examples/platform-identification.diag}
~~~
{: #ex-cca-platform-id title="Example CCA Platform Identification" }

Together, they are interpreted as a unique identifier of the CCA Platform.

### Reference Values {#sec-ref-values}

Reference Values carry measurements and other metadata associated with the updatable firmware of the CCA Platform.
CCA Platform is a collective term used to identify all the hardware and firmware components that comprise a CCA system.
Specifically these include the following:

- CCA system security domain
- Monitor security domain
- Realm Management Security domain

When appraising Evidence, the Verifier compares Reference Values against:

* The values found in the Software Components of the CCA Platform token (see {{Section 4.6 of -cca-token}}).
* The value set in the platform configuration of the CCA Platform token (see {{Section 4.5.3 of -cca-token}}).

Each measurement is encoded in a `measurement-map` of a CoMID `reference-triple-record`.
Since a `measurement-map` can encode one or more measurements, a single `reference-triple-record` can carry as many measurements as needed, provided they belong to the same CCA Platform identified in the subject of the triple.
A single `reference-triple-record` MUST completely describe the CCA Platform measurements.

#### CCA Platform Software Components

Each CCA Platform software component (called `arm-platform-sw-component` in {{Section 4.6.1 of -cca-token}}) is encoded in a `measurement-values-map` as defined in {{cddl-swcomp-mvm}}.

~~~ cddl
cca-swcomp-measurement-values-map = {
  ? &(version: 0) => cca-swcomp-version-map
  &(digests: 2) => cca-swcomp-digests-type
  ? &(name: 11) => cca-swcomp-name
  &(cryptokeys: 13) => [ cca-swcomp-signer-id ]
}

cca-swcomp-version-map = {
  &(version: 0) => text
}

cca-swcomp-digests-type = [ + cca-digest ]

cca-digest = [
  alg: text
  val: cca-hash-type
]

cca-hash-type = bytes .size 32 / bytes .size 48 / bytes .size 64

cca-swcomp-name = text

cca-swcomp-signer-id = #6.560(cca-hash-type)
~~~
{: #cddl-swcomp-mvm title="CCA Platform Software Component encoding"}

version (key 0):
: A `version-map` with its `version` field containing the version (key 4) of the `arm-platform-sw-component`.
The `version-scheme` field of the `version-map` MUST NOT be present.
This field is optional.

digests (key 2):
: Each array element encodes the "measurement value" (key 2) and "hash algorithm identifier" (key 6) of the `arm-platform-sw-component` in the `val` and `alg` entries, respectively.
The `alg` entry MUST use the text encoding.
The digests array MUST contain at least one entry and MAY contain more than one entry if multiple digests (obtained with different hash algorithms) of the same measured component exist.
If multiple entries exist, they MUST have different `alg` values.
This field is mandatory.

name (key 11):
: A text value containing the "component type" (key 1) of the `arm-platform-sw-component`.
This field is optional.

cryptokeys (key 13):
: An array with *only one* entry using the `tagged-bytes` variant of the `$crypto-key-type-choice`.
The entry contains the "signer id" (key 5) of the `arm-platform-sw-component`.
This field is mandatory.

Each `measurement-values-map` for a CCA Platform software component is wrapped in a `measurement-map` with an `mkey` using the text variant of the `$measured-element-type-choice`.
The value of the `mkey` MUST be "cca.software-component".
The `authorized-by` field of the `measurement-map` MUST NOT be present.
Find the related CDDL definitions in {{cddl-swcomp-mm}}.

~~~ cddl
cca-swcomp-measurement-map = {
  &(mkey: 0) => "cca.software-component"
  &(mval: 1) => cca-swcomp-measurement-values-map
}
~~~
{: #cddl-swcomp-mm title="CCA Platform Software Component measurement-map"}

#### CCA Platform Configuration

The CCA Platform configuration describes the set of chosen implementation options of the CCA Platform.
For example, this may include a description of the level of physical memory protection provided.

CCA Platform configuration is vendor-specific variable-length data.
Only some of the data may be security-relevant.
For these reasons, it is represented in a `raw-value` of the `measurement-values-map`, using the `tagged-masked-raw-value` variant of the `$raw-values-type-choice`.
Refer to {{Section 5.1.4.1.4.6 of -rats-corim}} for the details about the comparison algorithm.

~~~ cddl
cca-config-measurement-values-map = {
  &(raw-value: 4) => cca-tagged-masked-raw-value
}

cca-config-tagged-masked-raw-value = #6.563([
  value: bytes
  mask: bytes
])
~~~
{: #cddl-config-mvm title="CCA Platform Configuration measurement-map"}

The `measurement-values-map` for a CCA Platform configuration is wrapped in a `measurement-map` with an `mkey` using the text variant of the `$measured-element-type-choice`.
The value of the `mkey` MUST be "cca.platform-config".
There MUST be only one `measurement-map` with `mkey` "cca.platform-config" in the triple.

The `authorized-by` field of the `measurement-map` MUST NOT be present.
Find the related CDDL definitions in {{cddl-config-mm}}.

~~~ cddl
cca-config-measurement-map = {
  &(mkey: 0) => "cca.platform-config"
  &(mval: 1) => cca-config-measurement-values-map
}
~~~
{: #cddl-config-mm title="CCA Platform Software Component measurement-map"}

#### CoMID Example

An example CoMID containing one Reference Values triple with the expected values for both software components and platform configuration is given in {{ex-cca-platform-refval}}.

~~~ cbor-diag
{::include examples/platform-refval-meas.diag}
~~~
{: #ex-cca-platform-refval title="Example CCA Platform Reference Values" }

### Attestation Verification Keys {#sec-keys}

An Attestation Verification Key contains the public key associated with the CCA Platform Attestation Key (CPAK).
When appraising Platform Evidence, the Verifier uses the Implementation ID and Instance ID claims found in the Platform Token to identify the key that it shall use to verify the signature on the CCA Platform token.
This allows the Verifier to prove (or disprove) the Attester's claimed identity.

Each verification key is provided with the corresponding CCA Platform Instance and Implementation IDs in an `attest-key-triple-record`.
Specifically:

* The Instance and Implementation IDs are encoded in the `environment-map` as described in {{sec-cca-rot-id}};
* The CPAK public key uses the `tagged-pkix-base64-key-type` variant of the `$crypto-key-type-choice`.

The CPAK public key is a SubjectPublicKeyInfo {{-pkix-x509}} using the encoding defined in {{Section 13 of -pem}}.
There MUST be only one key in an `attest-key-triple-record`.

#### CoMID Example

The example in {{ex-cca-platform-iak}} shows the CCA Endorsement of type Attestation Verification Key carrying a secp256r1 EC public CPAK associated with Instance ID `4ca3...d296`.

~~~
{::include-fold examples/platform-iak.diag}
~~~
{: #ex-cca-platform-iak title="Example CCA Platform Attestation Verification Key" }

### Evidence Transformations

This section describes the transformations required to map a CCA Platform Token to its equivalent CoRIM internal representation.

{{trans-plat}} shows the complete transformation.

#### Platform Identification

The CCA Implementation and Instance IDs are used together to provide a unique identifer for the CCA platform.
The following function maps these IDs onto a CoRIM `environment-map`.

~~~ pseudocode
FUNC cca_platform_id_to_env(
    inst-id: arm-platform-instance-id-type,
    impl-id: arm-platform-implementation-id-type,
) -> environment-map {
    env := environment-map::NEW()
    env.class.class-id = tagged-bytes(impl-id)
    env.instance = tagged-ueid-type(inst-id)

    RETURN env
}
~~~
{: #trans-platform-id title="Transform CCA Platform IDs into Environment Map" }

#### Software Components

The following function maps a single CCA software component to a CoRIM element map.
The element identifier is "cca.software-component", and the element claims are synthesized from the CCA software component attributes using only the following default CoRIM `element-map` attributes: name, version, digests and cryptokeys.

~~~ pseudocode
FUNC element-from-cca-sw-component(
    C: arm-platform-sw-component,
) -> element-map {
    em := element-map::NEW()

    em.element-id = tstr("cca.software-component")

    em.element-claims.name = C.measurement-type
    em.element-claims.version.version = C.version

    digest := eatmc.digest(C.measurement-desc, C.measurement-value)
    em.element-claims.digests::APPEND(digest)

    signer := tagged-bytes(C.signer-id)
    em.element-claims.cryptokeys::APPEND(signer)

    RETURN em
}
~~~
{: #trans-sw-comp title="Transform a CCA Software Component into an Element Map" }

#### Platform Configuration

The following function maps the CCA platform configuration claim to a CoRIM element map.
The element identifier is "cca.platform-config", and the element claims use the standard raw-values attribute to represent the platform configuration value as `tagged-bytes`.

~~~ pseudocode
FUNC element-from-platform-config(
    C: arm-platform-config-type
) -> element-map {
    em := element-map::NEW()

    em.element-id = tstr("cca.platform-config")

    em.element-claims.raw-values = tagged-bytes(C)

    RETURN em
}
~~~
{: #trans-plat-conf title="Transform a CCA Plaform Config into an Element Map" }

#### Platform Token

The following function maps the CCA platform's claims set to a single CoRIM `ae-item`.

The environment is synthesized from instance and implementation identifiers.
Each software component is mapped to an `element-map` entry with identifier "cca.software-component".
The platform configuration is mapped to an `element-map` entry with identifier "cca.platform-config".

The process uses the functions defined in {{trans-platform-id}}, {{trans-sw-comp}}, and {{trans-plat-conf}}.

The process assumes that the profile of the CCA Platform claims-set is "tag:arm.com,2024:cca_platform#2.0.0".

~~~ pseudocode
FUNC transform(
    P: arm-platform-claims,
    cpak_pub: $crypto-key-type-choice
) -> ae-item {
    ASSERT::Equal(
        P.arm-platform-profile-label,
        "tag:arm.com,2024:cca_platform#2.0.0"
    )

    item := ae-item::NEW()

    item.addition.cmtype = evidence

    # map platform identifiers to environment
    item.addition.environment = cca_platform_id_to_env(
        P.arm-platform-instance-id-label,
        P.arm-platform-implementation-id-label
    )

    element-list = [ + element-map ]::NEW()

    # map software components to elements
    FOREACH c IN P.arm-platform-sw-components:
        e := element-from-sw-component(c)
        element-list::APPEND(e)

    # map platform config to element
    e := element-from-platform-config(P.arm-platform-config-label)
    element-list::APPEND(e)

    item.addition.element-list = element-list
    item.addition.profile = "tag:arm.com,2025:cca_platform#1.0.0"
    item.addition.authority::APPEND(cpak_pub)

    RETURN item
}
~~~
{: #trans-plat title="Transform a CCA Plaform into a CoRIM `ae` Relation" }

## Arm CCA Realm Endorsements {#realm-endorsements}

Arm CCA provides confidential computing environments, known as Realms, that enable application workloads requiring confidential execution to operate in isolation from the host hypervisor and any other concurrent workload.
Arm CCA allows the initial and run-time state of a Realm to be attested ({{Section 4.8 of -cca-token}}).

Realm Endorsements consist of Reference Values ({{sec-realm-ref-values}}), which are measurements of the configuration and contents of a Realm at the time of its activation, along with measurements of the software operating within the Realm, which can be extended throughout the Realm's lifetime.

Unlike the Platform, Realm Attestation Verification Key Endorsements are not necessary as the key material needed to verify the Realm Evidence is inline in the CCA Token ({{Section 3.2 of -cca-token}}).

### Arm CCA Realm Endorsement Profile

Arm CCA Realm Endorsements are carried in a CoMID within a CoRIM.

The profile attribute in the CoRIM MUST be present and MUST be the URI `tag:arm.com,2025:cca_realm#1.0.0` as shown in {{ex-cca-realm-profile}}.

~~~ cbor-diag
{::include examples/realm-profile.diag}
~~~
{: #ex-cca-realm-profile title="CoRIM profile for CCA Realm Endorsements version 1.0.0" }

### Realm Endorsements linkage to Realm {#realm-id}

Realms do not have *explicit* class or instance identifiers.
However, the Realm Initial Measurement (RIM) is unique and stable enough to serve as an identifier for the Realm Target Environment.
Therefore, this profile employs an `environment-map` with a class identifier that uses the `tagged-bytes` variant of the `$class-id-type-choice` to encode the RIM value ({{ex-cca-realm-identifiers}}).

~~~ cbor-diag
/ environment-map / {
  / comid.class / 0 : {
    / comid.class-id / 0 :
      / RIM as tagged-bytes / 560(
        h'311314ab73620350cf758834ae5c65d9
          e8c2dc7febe6e7d9654bbe864e300d49'
      )
  }
}
~~~
{: #ex-cca-realm-identifiers title="CCA Realm Identification" }

### Reference Values {#sec-realm-ref-values}

Reference Values carry measurements and other metadata associated with the CCA Realm.

Realm Reference Values comprise:

1. Realm Initial Measurements (RIM)
2. Realm Extended Measurements (REMs)
3. Realm Personalization Value (RPV)

All Realm Reference Values are carried in a `reference-triple-record` whose `environment-map` is as described in {{realm-id}}
The triple includes as many `measurement-map`s as needed to fully describe the Realm.

The `measurement-map` contents depend on the type of Reference Value.
For all, the `mkey` uses the text variant of the `$measured-element-type-choice`.
The value of the `mkey` MUST be "cca.rim" for the RIM measurement, "cca.rpv" for the RPV measurement, and "cca.rem0".."cca.rem3" for the REM measurements.
The `authorized-by` field of the `measurement-map` MUST NOT be present.

RIM and REMs are encoded as `digests` (key 2).

RPV is encoded using a `raw-value` (key 4) using the `tagged bytes` variant of the `$raw-value-type-choice`.

All the Realm Reference Values are optional except RIM, which is mandatory.

#### CoMID Example

An example CoMID containing one Reference Values triple with the expected values for a Realm is given in {{ex-cca-realm-refval}}.

~~~
{::include examples/realm-refval.diag}
~~~
{: #ex-cca-realm-refval title="CCA realm identifiers" }

### Evidence Transformations

This section describes the transformations required to map a CCA Realm Token to its equivalent CoRIM internal representation.

{{trans-realm}} shows the complete transformation.

#### Realm Identification

The following function maps the CCA Realm Initial Measurement - which, as discussed in {{realm-id}}, provides a stable identifier for the Realm - onto a CoRIM `environment-map`.

~~~ pseudocode
FUNC cca_realm_id_to_env(
    rim: cca-realm-measurement-type
) -> environment-map {
    env := environment-map::NEW()
    env.class.class-id = tagged-bytes(rim)

    RETURN env
}
~~~
{: #trans-realm-id title="Transform a CCA Realm Initial Measurement into an Element Map" }

#### Realm Initial Measurements

The following function maps the CCA Realm Initial Measurement claim to a CoRIM element map.
The element identifier is "cca.rim", and the element claims use the standard digests attribute to represent the RIM value, using the digest algorithm taken from the Realm hash algorithm ID claim.

~~~ pseudocode
FUNC element-from-rim(
    rim-value: cca-realm-measurement-type,
    rim-algo: text
) -> element-map {
    em := element-map::NEW()

    em.element-id = tstr("cca.rim")

    digest := eatmc.digest(rim-algo, rim-value)
    em.element-claims.digests::APPEND(digest)

    RETURN em
}
~~~
{: #trans-rim title="Transform a CCA Realm Initial Measurement into an Element Map" }

#### Realm Extended Measurements

The following function maps the i-th (0..3) bank of a CCA Realm Extended Measurements claim to a CoRIM element map.
The element identifier is one of "cca.rem0".."cca.rem3", depending on the bank index, and the element claims use the standard digests attribute to represent the REM value, using the digest algorithm taken from the Realm hash algorithm ID claim.

~~~ pseudocode
FUNC element-from-rem(
    rem-index: uint,
    rem-value: cca-realm-measurement-type,
    rim-algo: text
) -> element-map {
    em := element-map::NEW()

    em.element-id = tstr("cca.rem" + rem-index)

    digest := eatmc.digest(rem-algo, rem-value)
    em.element-claims.digests::APPEND(digest)

    RETURN em
}
~~~
{: #trans-rem title="Transform a CCA Realm Extended Measurement Bank into an Element Map" }

#### Realm Personalization Value

The following function maps the CCA realm personalization value claim to a CoRIM element map.
The element identifier is "cca.rpv", and the element claims use the standard raw-values attribute to represent the personalization value as tagged-bytes.

~~~ pseudocode
FUNC element-from-rpv(
    rpv: cca-realm-personalization-value-type
) -> element-map {
    em := element-map::NEW()

    em.element-id = tstr("cca.rpv")

    em.element-claims.raw-values = tagged-bytes(rpv)

    RETURN em
}
~~~
{: #trans-rpv title="Transform a CCA Realm Personalization Value into an Element Map" }

#### Realm Token

The following function maps the CCA realm's claims set to a single CoRIM `ae-item`.

The environment is synthesized from the RIM.
Each REM bank, if present, is mapped to an element-map entry with identifier "cca.rem0".."cca.rem3".
The personalization value, if present, is mapped to an element-map entry with identifier "cca.rpv".

The process uses the functions defined in {{trans-realm-id}}, {{trans-rim}}, {{trans-rem}}, and {{trans-rpv}}.

The process assumes that the profile of the CCA Realm claims-set is "tag:arm.com,2024:realm#2.0.0".

~~~ pseudocode
FUNC transform(
    R: cca-realm-claims
) -> ae-item {
    ASSERT::Equal(
        R.cca-realm-profile-label,
        "tag:arm.com,2024:realm#2.0.0"
    )

    item := ae-item::NEW()

    item.addition.cmtype = evidence

    # map platform identifiers to environment
    item.addition.environment = cca_realm_id_to_env(
        R.cca-realm-initial-measurement-label
    )

    element-list = [ + element-map ]::NEW()

    # map realm initial measurement to element
    e := element-from-rim(R.cca-realm-profile-label)
    element-list::APPEND(e)

    # map optional REMs
    IF R.cca-realm-extensible-measurements:
        FOREACH idx, r IN R.cca-realm-extensible-measurements:
            e := element-from-rem(idx, r, R.cca-realm-hash-algo-id-label)
            element-list::APPEND(e)

    # map optional RVP
    IF R.cca-realm-personalization-value:
        e := element-from-rpv(R.arm-platform-config-label)
        element-list::APPEND(e)

    item.addition.element-list = element-list
    item.addition.profile = "tag:arm.com,2025:cca_realm#1.0.0"
    item.addition.authority::APPEND(R.cca-realm-public-key-label)

    RETURN item
}
~~~
{: #trans-realm title="Transform a CCA Realm into a CoRIM `ae` Relation" }

# Security Considerations

[^todo]

# IANA Considerations

This document makes no requests to IANA.

--- back

# Acknowledgements
{:unnumbered}

[^todo]

[^todo]: TODO
