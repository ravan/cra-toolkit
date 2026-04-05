# The EU Cyber Resilience Act

**Regulation (EU) 2024/2847** of the European Parliament and of the Council, adopted on 23 October 2024 at Strasbourg and published in the Official Journal of the European Union on 20 November 2024.

The Cyber Resilience Act (CRA) is the first EU-wide horizontal cybersecurity regulation for **products with digital elements**. It establishes harmonised cybersecurity requirements that apply uniformly across all EU Member States, covering the entire lifecycle of hardware and software products — from design and development through to market placement and ongoing maintenance.

---

## Key Enforcement Dates

<figure markdown="span">
  ![CRA Overview](../assets/diagrams/cra-overview.svg){ width="100%" }
  <figcaption>Structure of the EU Cyber Resilience Act — key dates, articles, annexes, product categories, and penalties.</figcaption>
</figure>

| Date | Milestone |
|------|-----------|
| **23 October 2024** | Regulation adopted at Strasbourg |
| **11 June 2026** | Conformity assessment body rules apply (Chapter IV, Articles 35-51) |
| **11 September 2026** | Article 14 reporting obligations apply |
| **11 December 2027** | Full application of all provisions |

---

## Who the CRA Affects

The CRA assigns obligations to four categories of economic operators and actors in the supply chain.

### Manufacturers (Article 13)

Manufacturers are the **primary obligation holders** under the CRA. They must:

- Design, develop, and produce products that comply with the **essential cybersecurity requirements** set out in Annex I
- Perform a cybersecurity risk assessment and document it in the technical documentation (Annex VII)
- Exercise due diligence when integrating third-party components
- Apply a conformity assessment procedure (Annex VIII) before placing the product on the market
- Provide security updates for the defined support period (minimum 5 years or the expected product lifetime)
- Report actively exploited vulnerabilities and severe incidents (Article 14)

### Importers (Article 19)

Importers must verify manufacturer compliance before placing products on the EU market:

- Ensure the manufacturer has carried out the appropriate conformity assessment procedure
- Verify the product bears the CE marking and is accompanied by the required documentation
- Ensure the EU declaration of conformity (Annex V) and technical documentation are available
- Not place a product on the market where they have reason to believe it does not comply

### Distributors (Article 20)

Distributors must act with due care in relation to the CRA requirements:

- Verify the product bears the CE marking
- Verify that the manufacturer and, where applicable, the importer have complied with their obligations
- Not make a product available on the market where they have reason to believe it does not comply
- Inform the manufacturer or importer and market surveillance authorities of identified risks

### Open-Source Software Stewards (Article 24)

Open-source software stewards — legal persons that systematically provide support for the development of free and open-source software intended for commercial activities — must:

- Put in place and document a **cybersecurity policy** to foster development of secure products
- Facilitate **voluntary vulnerability reporting** by developers
- Cooperate with **market surveillance authorities** on mitigating cybersecurity risks
- Provide documentation, including an SBOM, upon request from authorities

!!! note "Open-Source Exemption"
    Free and open-source software developed or supplied outside the course of a commercial activity is **excluded** from the CRA's scope. The steward obligations apply only where a legal person systematically supports open-source software intended for commercial use.

---

## Structure of the Act

### Key Articles

| Article | Title | Summary |
|---------|-------|---------|
| Art. 13 | Obligations of manufacturers | Core obligations: design products to meet Annex I requirements, perform risk assessment, apply conformity assessment, provide security updates |
| Art. 14 | Reporting obligations | Mandatory notification to ENISA and national CSIRTs of actively exploited vulnerabilities (24h early warning, 72h notification, 14d report) and severe incidents |
| Art. 19 | Obligations of importers | Verify manufacturer compliance, CE marking, and documentation before EU market placement |
| Art. 20 | Obligations of distributors | Verify CE marking and that manufacturer/importer have met their obligations |
| Art. 24 | Obligations of open-source software stewards | Cybersecurity policy, voluntary vulnerability reporting facilitation, cooperation with market surveillance |
| Art. 31 | Technical documentation | Manufacturers must draw up technical documentation per Annex VII before placing the product on the market |
| Art. 32 | Conformity assessment procedures | Defines which conformity assessment procedures manufacturers must apply, referencing Annex VIII |

### Annexes

| Annex | Title | Summary |
|-------|-------|---------|
| Annex I | Essential cybersecurity requirements | Part I: security properties (confidentiality, integrity, availability, access control, etc.). Part II: vulnerability handling requirements (identify/document vulnerabilities, apply security updates, disclose and address without delay) |
| Annex II | Information and instructions to the user | Required user-facing documentation including manufacturer identity, point of contact, support period, SBOM information, and instructions for secure installation/use |
| Annex III | Important products with digital elements | **Class I**: identity management, browsers, password managers, VPNs, network management, SIEM, boot managers, PKI, OS, routers, smart home devices, wearables. **Class II**: hypervisors, container runtimes, firewalls, IDS/IPS, tamper-resistant microprocessors/controllers |
| Annex IV | Critical products with digital elements | Hardware devices with security boxes, smart meter gateways, smartcards and similar secure elements |
| Annex V | EU declaration of conformity | Required content and format for the manufacturer's formal declaration of conformity |
| Annex VII | Technical documentation content | Detailed list of elements required: product description, risk assessment, design/development information, vulnerability handling process documentation, applied standards, test reports |
| Annex VIII | Conformity assessment procedures | **Module A** (internal control — self-assessment), **Module B+C** (EU-type examination + conformity to type), **Module H** (full quality assurance) |

---

## Product Categories

The CRA establishes a tiered classification system that determines the conformity assessment procedure a product must undergo.

### Default Products

The majority of products with digital elements fall into the **default category**. These require only an internal control assessment (**Module A**, Annex VIII Part I) — effectively a self-assessment by the manufacturer.

### Important Products — Class I (Annex III, Part I)

Products with a higher cybersecurity risk that may use harmonised standards or, where unavailable, must undergo third-party assessment:

- Identity management systems and privileged access management software
- Standalone and embedded browsers
- Password managers
- Virtual private networks (VPNs)
- Network management systems
- Security information and event management (SIEM) systems
- Boot managers and UEFI boot management
- Public key infrastructure and digital certificate issuance software
- Physical and virtual network interfaces
- Operating systems
- Routers and modems for internet connection
- Security-relevant microprocessors
- Smart home general-purpose virtual assistants
- Smart home products with security functionalities (door locks, cameras, baby monitors, alarm systems)
- Connected toys with social interactive features
- Personal wearable health products

### Important Products — Class II (Annex III, Part II)

Products requiring **mandatory third-party assessment** due to their elevated risk profile:

- Hypervisors and container runtime systems that support virtualised execution of operating systems
- Firewalls, intrusion detection and prevention systems (IDS/IPS)
- Tamper-resistant microprocessors
- Tamper-resistant microcontrollers

### Critical Products (Annex IV)

The highest-risk category, potentially requiring **European cybersecurity certification**:

- Hardware devices with security boxes
- Smart meter gateways
- Smartcards or similar devices, including secure elements

---

## Penalties

The CRA establishes significant penalties for non-compliance, enforced by market surveillance authorities in each Member State.

| Violation | Maximum Penalty |
|-----------|----------------|
| Non-compliance with essential cybersecurity requirements (Annex I) | **EUR 15,000,000** or **2.5%** of total worldwide annual turnover, whichever is higher |
| Non-compliance with other obligations under the Regulation | **EUR 10,000,000** or **2%** of total worldwide annual turnover, whichever is higher |
| Supply of incorrect, incomplete, or misleading information to authorities | **EUR 5,000,000** or **1%** of total worldwide annual turnover, whichever is higher |

!!! warning "Enforcement Timeline"
    While the full CRA does not apply until 11 December 2027, Article 14 reporting obligations become enforceable on **11 September 2026**. Organisations should begin preparing compliance processes well in advance.

---

!!! tip "Toolkit Implementation"
    The CRA Compliance Toolkit automates key requirements across the CRA.
    See the [Compliance Mapping](compliance-mapping.md) for a complete requirement-to-tool matrix.
