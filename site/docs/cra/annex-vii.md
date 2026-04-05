# Annex VII — Technical Documentation

Annex VII of Regulation (EU) 2024/2847 (the Cyber Resilience Act) specifies the minimum content that must be included in the **technical documentation** referred to in Article 31. This documentation is central to demonstrating conformity with the essential cybersecurity requirements and must be maintained throughout the product's support period.

Article 32 then defines the **conformity assessment procedures** (detailed in Annex VIII) that manufacturers must follow depending on their product's classification.

---

## Content of Technical Documentation

The technical documentation referred to in Article 31 shall contain at least the following information, as applicable:

### 1. General description of the product with digital elements

Including:

**(a)** Its intended purpose;

**(b)** Versions of software affecting compliance with the essential cybersecurity requirements;

**(c)** Where applicable, hardware photographs or illustrations showing external features, marking, and internal layout;

**(d)** User information and instructions as set out in [Annex II](annex-i.md).

### 2. Design, development, production and vulnerability handling processes

Including:

**(a)** Necessary information on the design and development of the product with digital elements, including, where applicable, drawings and schemes and a description of the system architecture explaining how software components build on or feed into each other and integrate into the overall processing;

**(b)** Necessary information and specifications of the vulnerability handling processes put in place by the manufacturer, including:

- The software bill of materials (SBOM);
- The coordinated vulnerability disclosure policy;
- Evidence of a contact address for the reporting of vulnerabilities;
- A description of the technical solutions chosen for the secure distribution of updates.

**(c)** Necessary information and specifications of the production and monitoring processes and their validation.

### 3. Cybersecurity risk assessment

An assessment of the cybersecurity risks against which the product with digital elements is designed, developed, delivered and maintained pursuant to Article 13, including how the essential cybersecurity requirements set out in [Part I of Annex I](annex-i.md#part-i-cybersecurity-requirements-relating-to-the-properties-of-products-with-digital-elements) are applicable.

### 4. Support period determination

Relevant information taken into account for the determination of the support period pursuant to Article 13(8) of the product with digital elements.

### 5. Harmonised standards and specifications

A list of the harmonised standards applied in full or in part, the references of which have been published in the Official Journal of the European Union, common specifications as referred to in Article 27, or European cybersecurity certification schemes as referred to in Article 27(8). Where those harmonised standards, common specifications, or European cybersecurity certification schemes have not been applied, descriptions of the solutions adopted to meet the essential cybersecurity requirements set out in Parts I and II of [Annex I](annex-i.md).

### 6. Test reports

Reports of the tests carried out to verify the conformity of the product with digital elements and of the vulnerability handling processes with the applicable essential cybersecurity requirements set out in Parts I and II of [Annex I](annex-i.md).

### 7. EU declaration of conformity

A copy of the EU declaration of conformity.

### 8. Software bill of materials

Where applicable, the software bill of materials (SBOM), further to a reasoned request from a market surveillance authority.

---

## Conformity Assessment Procedures (Article 32)

Article 32 defines which conformity assessment procedures (set out in Annex VIII) manufacturers must follow. The applicable procedure depends on the product's classification.

### Module A — Internal Control

**Part I of Annex VIII.** The manufacturer self-declares conformity. Under this procedure, the manufacturer:

- Draws up the technical documentation per Annex VII;
- Ensures that the design, development, and production processes and their monitoring ensure compliance of the product with digital elements with the essential cybersecurity requirements;
- Affixes the CE marking.

Module A is available for **all default-category products** (Art. 32(1)(a)). It is also available for **free and open-source software manufacturers** of important or critical products, provided they make the technical documentation publicly available (Art. 32(5)).

### Module B + C — EU-Type Examination + Internal Production Control

**Parts II and III of Annex VIII.** A notified body examines the technical design and development of the product with digital elements and issues an **EU-type examination certificate** confirming that the design meets the essential cybersecurity requirements. The manufacturer then ensures that production conforms to the approved type.

Module B+C is **required for Important Class I products** where harmonised standards, common specifications, or European cybersecurity certification schemes have not been fully applied (Art. 32(2)). It is also an option for Important Class II products.

### Module H — Full Quality Assurance

**Part IV of Annex VIII.** A notified body assesses and approves the manufacturer's **quality system** for the design, development, production, and final product testing of the product with digital elements. The notified body conducts ongoing surveillance of the quality system.

Module H is **required for Important Class II products** (Art. 32(3)). It is also available as an alternative to Module B+C for Important Class I products.

### Critical Products (Annex IV)

Products listed in **Annex IV** (critical products with digital elements) must use a **European cybersecurity certification scheme** adopted pursuant to Regulation (EU) 2019/881, at assurance level at least "substantial" as referred to in Article 8(1). Where no such certification scheme exists or where it does not cover all essential cybersecurity requirements, manufacturers must fall back to **Module B+C** or **Module H** (Art. 32(4)).

---

## Conformity Assessment Summary

| Product Category | Available Procedures | Reference |
|---|---|---|
| Default | Module A (internal control) | Art. 32(1)(a) |
| Important Class I | Module A (if harmonised standards applied), Module B+C, Module H | Art. 32(1-2) |
| Important Class II | Module B+C, Module H | Art. 32(3) |
| Critical (Annex IV) | Cybersecurity certification scheme, or Module B+C/H | Art. 32(4) |
| Free/open-source (Important/Critical) | Module A (if technical docs are public) | Art. 32(5) |

---

!!! tip "Toolkit Implementation"
    The `cra evidence` tool bundles all required technical documentation into a signed evidence package.
    It validates completeness against Annex VII requirements and cross-validates artifact consistency.
    See [Evidence — Bundling & Signing](../tools/evidence.md).
