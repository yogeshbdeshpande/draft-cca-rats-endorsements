---
title: A CoRIM Profile for Arm's Confidential Computing Architecture (CCA)
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

Arm CCA attestation scheme is a composite attestation scheme which comprises a CCA Platform Attestation & a Realm Attestation {{CCA-ARCH}}.
Hence appraisal of Arm CCA attestation needs endorsements for both CCA Platform and CCA Realm. This draft documents both the CCA platform and realm endorsements.

## Arm CCA Platform Endorsements

There are two types of CCA Platform Endorsements:

* Reference Values ({{sec-ref-values}}), i.e., measurements of the CCA Platform firmware.
* Attestation Verification Claims ({{sec-keys}}), i.e., cryptographic keys that can be used to verify signed attestation token produced by the CCA platform, along with the identifiers that bind the keys to their platform instances.

### Arm CCA Platform Endorsement Profile

Arm CCA platform endorsements are carried in one or more CoMIDs inside a CoRIM.

The profile attribute in the CoRIM MUST be present and MUST have a single entry
set to the uri `http://arm.com/cca/ssd/1` as shown in {{ex-cca-platform-profile}}.

~~~
{::include examples/platform-profile.diag}
~~~
{: #ex-cca-platform-profile title="CCA platform profile version 1, CoRIM profile" }

### Arm CCA Platform Endorsements linkage to CCA Platform
{: #sec-cca-rot-id}

Each CCA Platform Endorsement - be it a Reference Value or Attestation Verification Key
is associated with a unique CCA platform identifier. A CCA platform
identifier known as CCA Platform Implementation ID (see {{Section 4.4.2 of -cca-token}})
uniquely identifies a class of CCA platform to which the manufacturer/endorser links the supplied
Endorsements (Reference Values & Attestation Verification Keys) for a CCA platform.

In order to support CCA Implementation IDs, the CoMID type
`$class-id-type-choice` is extended as follows {{ex-cca-platform-impl-id}}:

~~~
{::include cca-ext/tagged-cca-impl-id.cddl}
~~~
{: #ex-cca-platform-impl-id title="Example CCA Platform Implementation ID" }

Besides, a CCA Endorsement can be associated with a specific instance of a
certain CCA Platform implementation - as is the case of Attestation Verification Claims.  A CCA
Attestation Verification Claims are associated with a CCA platform instance by means of the Instance ID
(see Section 4.4.1 of -cca-token}}) and its platform Implementation ID.

These identifiers are typically found in the subject of a CoMID triple, encoded in an `environment-map` as shown in {{ex-cca-platform-id}}.

~~~
{::include examples/platform-identification.diag}
~~~
{: #ex-cca-platform-id title="Example CCA Platform Identification" }

Optional `vendor` and `model` can be specified as well. Together, they are
interpreted as a unique identifier of the CCA platform.
Consistently providing a product identifier is RECOMMENDED.

### Reference Values
{: #sec-ref-values}

Reference Values carry measurements and other metadata associated with the updatable firmware of CCA platform. The CCA platform is a collective term used to identify all the hardware and firmware components that comprise a CCA system. Specifically these include the following:

- CCA system security domain
- Monitor security domain
- Realm Management Security domain

When appraising Evidence, the Verifier compares Reference Values against:

* The values found in the Software Components of the CCA platform token (see {{Section 4.6 of -cca-token}}).
* The value set in the platform configuration of the CCA platform token (see {{Section 4.5.3 of -cca-token}}).

Each measurement is encoded in a `measurement-map` of a CoMID
`reference-triple-record`.  Since a `measurement-map` can encode one or more
measurements, a single `reference-triple-record` can carry as many measurements as needed, provided they belong to the same CCA platform identified in the subject of
the "reference value" triple.  A single `reference-triple-record` SHALL
completely describe the CCA platform measurements.

#### CCA Platform Software Components
For the Reference Values of CCA platform software components the identifier of a measured software component is encoded in a `arm-swcomp-id` object as follows {{ex-swcomp-id}}:

~~~
{::include cca-ext/swcomp-id.cddl}
~~~
{: #ex-swcomp-id title="Example SW Component ID" }

The semantics of the codepoints in the `arm-swcomp-id` map are equivalent to those in the `cca-platform-sw-component` map defined in {{Section 4.6.1 of -cca-token}}.  The `arm-swcomp-id` MUST uniquely identify a given software component within the CCA platform / product.

In order to support CCA Reference Value identifiers, the CoMID type
`$measured-element-type-choice` is extended as follows{{ex-swcomp-id-ext}}:

~~~
{::include cca-ext/swcomp-id-ext.cddl}
~~~
{: #ex-swcomp-id-ext title="Example SW Component ID Extension" }

and automatically bound to the `comid.mkey` in the `measurement-map`.

The raw measurement is encoded in a `digests-type` object in the
`measurement-values-map`.  The `digests-type` array MUST contain at least one entry. The `digests-type` array MAY contain more than one entry if multiple digests (obtained with different hash algorithms) of the same measured component exist. Refer below {{ex-cca-platform-refval-meas}}.

#### CCA Platform Configuration

A Reference value for CCA platform configuration describes the set of chosen implementation options of the CCA platform. As an example, these may include a description of the level of physical memory protection which is provided.

CCA platform configuration reference value represent vendor specific variable length data. As a result, in the CCA platform CoRIM profile, it is represented in a `measurement-values-map` using `raw-values` set to `tagged-bytes` to express a variable length byte string, representing platform configuration data.

$raw-value-type-choice /= tagged-bytes

#### Complete Representation

The complete representation of CCA Platform Reference Values is given in {{ex-cca-platform-refval-meas}} and {{ex-cca-platform-refval-cfg}}.

~~~
{::include examples/platform-refval-meas.diag}
~~~
{: #ex-cca-platform-refval-meas title="Example CCA SW Component Reference Value" }

~~~
{::include examples/platform-refval-cfg.diag}
~~~
{: #ex-cca-platform-refval-cfg title="Example CCA Platform Configuration Reference Values" }

### Attestation Verification Claims
{: #sec-keys}

Attestation Verification Claim carries the verification key associated with
the Initial Attestation Key (IAK) of a CCA platform. When appraising Evidence,
the Verifier uses the Implementation ID and Instance ID claims (see
{{sec-cca-rot-id}}) to retrieve the verification key that it SHALL use to check the signature on the CCA platform token.  This allows the Verifier to prove (or disprove) the Attester's claimed identity.

Each verification key is provided alongside the corresponding CCA platform Instance
and Implementation IDs (and, possibly, a CCA platform product identifier) in an
`attest-key-triple-record`.  Specifically:

* The Instance and Implementation IDs are encoded in the environment-map as shown in {{ex-cca-platform-id}}
* The IAK public key is set using `$crypto-key-type-choice` set to tagged-pkix-base64-key-type. The IAK public key is a PEM-encoded SubjectPublicKeyInfo {{-pkix-x509}}. There MUST be only one key in an `attest-key-triple-record`;

The example in {{ex-cca-platform-iak}} shows the CCA Endorsement of type Attestation Verification Key carrying a secp256r1 EC public IAK associated with Instance ID `4ca3...d296`.

~~~
{::include examples/platform-iak.diag}
~~~
{: #ex-cca-platform-iak title="Example CCA Platform Attestation Verification Key" }

## Arm CCA Realm Endorsements

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

The profile attribute in the CoRIM MUST be present and MUST have a single entry
set to the uri `http://arm.com/cca/realm/1` as shown in {{ex-cca-realm-profile}}.

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
