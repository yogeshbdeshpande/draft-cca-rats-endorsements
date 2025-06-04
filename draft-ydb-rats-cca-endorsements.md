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
Appraising Arm CCA Evidence requires endorsements for both the Platform and Realm.
This document outlines the Platform and Realm endorsements in {{sec-platform-endorsements}} and {{realm-endorsements}}, respectively.

## Arm CCA Platform Endorsements {#sec-platform-endorsements}

There are two types of CCA Platform Endorsements:

* Reference Values ({{sec-ref-values}}), i.e., measurements of the CCA Platform firmware.
* Attestation Verification Keys ({{sec-keys}}), i.e., cryptographic keys that can be used to verify Evidence produced by the CCA Platform, along with the identifiers that link the keys to their platform instances.

### Arm CCA Platform Endorsement Profile

Arm CCA Platform endorsements are carried in one or more CoMIDs inside a CoRIM.
The profile attribute in the CoRIM MUST be present and MUST be the URI `tag:arm.com,2025:cca_platform#1.0.0`, as shown in {{ex-cca-platform-profile}}.

~~~
{::include examples/platform-profile.diag}
~~~
{: #ex-cca-platform-profile title="CCA Platform profile version 1, CoRIM profile" }

### Arm CCA Platform Endorsements linkage to CCA Platform {#sec-cca-rot-id}

Each CCA Platform Endorsement, be it a Reference Value or an Attestation Verification Key, is associated with a unique identifier known as CCA Platform Implementation ID (see {{Section 4.4.2 of -cca-token}}).
The Implementation ID uniquely identifies a given implementation of a CCA Platform and it used by the Endorser or Reference Value Provider as an anchor to which Reference Values and Attestation Verification Keys for a CCA Platform are linked.

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

Each CCA Platform software component is encoded in a `measurement-values-map` as defined in {{cddl-swcomp-mvm}}.

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

cca-swcomp-signer-id = #6.560(cca-hash-type)

cca-hash-type = bytes .size 32 / bytes .size 48 / bytes .size 64

cca-digest = [
  alg: text
  val: cca-hash-type
]

cca-swcomp-digests-type = [ + cca-digest ]

cca-swcomp-name = text
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
: An array with only one entry using the `tagged-bytes` variant of the `$crypto-key-type-choice`.
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

An example CoMID containing one Reference Values triple containing expected values for both software components and platform configuration is given in {{ex-cca-platform-refval}}.

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
The CPAK public key is a PEM-encoded SubjectPublicKeyInfo {{-pkix-x509}}.
There MUST be only one key in an `attest-key-triple-record`.

The example in {{ex-cca-platform-iak}} shows the CCA Endorsement of type Attestation Verification Key carrying a secp256r1 EC public CPAK associated with Instance ID `4ca3...d296`.

~~~
{::include examples/platform-iak.diag}
~~~
{: #ex-cca-platform-iak title="Example CCA Platform Attestation Verification Key" }

## Arm CCA Realm Endorsements {#realm-endorsements}

Arm CCA Realm provides a protected execution environment for applications executing within a Realm. A Realm Endorsements comprise of:

* Reference Values ({{sec-realm-ref-values}}), i.e., measurements of the configuration and contents of a Realm at the time of its activation along with measurements of software running inside Realm, which can be extended during the lifetime of a Realm.

Please note that there are no Realm Trust Anchor Endorsements needed from supply chain as they are present inline in the Attestation Evidence.

### Realm Endorsements linkage to Realm

Each Realm has a unique execution context and hence a unique Realm instance. Each Realm is uniquely identified in the Arm CCA system. For a Realm its Endorsements are associated to this unique instance. The Realm instance is a vendor defined variable length identifier. Hence in this profile, it is represented in a CoMID inside an `environment-map` with `$instance-id-type-choice` set to `tagged-bytes`, i.e. an opaque, variable-length byte string. In this profile of CCA Endorsements, the Realm Initial Measurements are set in `tagged-bytes` to represent Realm instance.

When supplying Realm Endorsements, a supplier of one or more Realms may wish to identify itself. Hence the following class related elements in the `environment-map` of a  `comid` can be used. See {{ex-cca-realm-identifiers}}

In the `class-map` select `vendor` name and/or `class-id` set as `UUID` representing unique identity of the Realm owner.

$class-id-type-choice /= tagged-uuid-type

vendor => `tstr` to represent vendor name

~~~
{::include examples/realm-identification.diag}
~~~
{: #ex-cca-realm-identifiers title="CCA realm identifiers" }

### Arm CCA Realm Endorsement Profile

Arm CCA Realm Endorsements are carried in a CoMID inside a CoRIM.

The profile attribute in the CoRIM MUST be present and MUST be the URI `tag:arm.com,2025:cca_realm#1.0.0` as shown in {{ex-cca-realm-profile}}.

~~~
{::include examples/realm-profile.diag}
~~~
{: #ex-cca-realm-profile title="CCA realm profile version 1, CoRIM profile" }

### Reference Values
{: #sec-realm-ref-values}

Reference Values carry measurements and other metadata associated with the
CCA Realm.

Realm reference values comprise of:

1. Realm Initial Measurements (RIM)
2. Realm Extended Measurements (REMs)
3. Realm Personalization Value (RPV)

RIM and REMs are encoded in a `measurement-values-map` (in a `measurement-map`) of a CoMID `reference-triple-record`. Inside `measurement-values-map` these measurements are carried as `integrity-registers` map. Integrity Registers map is used to group together one or more measured objects pertaining to an environment. Please refer to {{-rats-corim}} for details about Integrity Register map.

All the measured objects in an Integrity Registers map are explicitly named. In the context of Realms, the measured objects are RIM and REMs. Inside Integrity Register map, RIM is uniquely identified by the name "rim", while REMs which is an array of measurements from 1..4 are uniquely identified by the coresponding name "rem0".."rem3".

Realm Personalization Value, (RPV) is an optional identity used by a Realm endorser to uniquely identify multiple Realms which all have the same RIM. RPV if provided is a fixed length 64 bytes identifier. In this profile, RPV is represented using Raw Value Measurements in a `measurement-values-map`, with raw value type choice set to `tagged-bytes`. See {{ex-cca-realm-refval}}

$raw-value-type-choice /= tagged-bytes

Given below is the complete example of a Realm Endorsements.

~~~
{::include examples/realm-refval.diag}
~~~
{: #ex-cca-realm-refval title="CCA realm identifiers" }

# Security Considerations

<cref>TODO</cref>

# IANA Considerations

## CBOR Tag Registrations

IANA is requested to allocate the following tags in the "CBOR Tags" registry
{{!IANA.cbor-tags}}, preferably with the specified value:

| Tag | Data Item | Semantics |
|---
| 600 | tagged bytes | CCA Implementation ID ({{sec-cca-rot-id}} of {{&SELF}}) |
| 601 | tagged map | CCA Software Component Identifier ({{sec-ref-values}} of {{&SELF}}) |
{: #tbl-psa-cbor-tag title="CoRIM CBOR Tags"}

# Acknowledgements


<cref>TODO</cref>
