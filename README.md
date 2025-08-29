# Anatomy of a Reconnaissance Campaign: Deconstructing the Bulletproof Hosting Ecosystem of AS401116, AS401120, and AS215540


## Executive Summary

The coordinated reconnaissance wave targeting Cisco Adaptive Security Appliance (ASA) devices in late August 2025 was a deliberate, centrally-managed operation, not anomalous internet background noise. This campaign was launched from a purpose-built, abuse-tolerant infrastructure cluster comprising three key Autonomous Systems (ASNs): **AS401116 (NYBULA)**, **AS401120 (CHEAPY-HOST)**, and **AS215540 (Global Connectivity Solutions LLP)**.

The surgical precision, timing, and uniformity of the activity indicate a sophisticated actor preparing for subsequent, targeted exploitation. This investigation unmasks the complex web of shell companies and individuals behind this infrastructure, revealing a sophisticated network designed for obfuscation and operational resilience.

Analysis of corporate filings and open-source intelligence directly links AS215540 to **Russian national Yevgeniy Valentinovich Marinko**, a known cybercriminal with a documented history of trading stolen credentials and involvement in malware-related fraud. The corporate structure is further tied to **Latvian national Kirils Pestuns**, whose company formation agency, *ComForm Solutions*, has been implicated in large-scale money laundering schemes, including the *“Russian Laundromat”* scandal detailed in the *FinCEN Files* investigation.

This infrastructure is not a single-purpose tool but a component of a broader, resilient ecosystem that provides services to a spectrum of malicious actors. Evidence confirms this network has been instrumental in hosting **command-and-control (C2) servers** for Russian-aligned espionage groups (*Gamaredon*), malware operations (*BoneSpy, PlainGnome*), and the persistent pro-Kremlin *“Doppelganger”* disinformation campaign.

The convergence of cybercrime, espionage, and information operations on this shared infrastructure highlights a blended threat that transcends traditional actor-motive classifications.

The observed activity represents the initial reconnaissance phase of a classic attack playbook. The operators have now mapped vulnerable Cisco ASA devices globally and are positioned to launch follow-on attacks, including **Denial of Service (DoS)** for extortion, **information disclosure** for credential theft, and **Remote Code Execution (RCE)** for network intrusion and ransomware deployment.

For network defenders, this activity serves as a critical early warning. The operational model—combining jurisdictional arbitrage, disposable network assets, and opaque corporate layering—presents a formidable challenge, requiring a multi-faceted defensive strategy that incorporates **network, corporate, and geopolitical threat intelligence**.

## The Catalyst: A Multi-Phased Cisco ASA Reconnaissance Wave

### Introduction to the Observed Activity

In late August 2025, a significant and highly coordinated reconnaissance campaign targeting Cisco ASA appliances was detected. This activity, captured by a network of honeypots, deviated sharply from historical patterns of low-level, opportunistic scanning typically observed against these devices.

The campaign's intensity, uniformity, and concentration within a small set of abuse-tolerant ASNs strongly suggest it was a preparatory phase for widespread, targeted exploitation.

The timing of this wave, coinciding with the public disclosure of new Cisco ASA and Firepower Threat Defense (FTD) security advisories, indicates an agile and operationally mature adversary systematically mapping vulnerable internet-facing infrastructure.

This section deconstructs the campaign across its four distinct phases, establishing the evidentiary basis for the subsequent infrastructure and actor analysis.


### Phase 1: Baseline Background Noise (31 July – 12 Aug 2025)

The initial two-week period provided a crucial baseline against which the subsequent escalation was measured. During this phase, the honeypot infrastructure recorded approximately **9,463 events** from **210 unique IP addresses**.

This activity was characteristic of generic internet background noise: scattered, opportunistic probes originating from a diverse and geographically dispersed mix of sources, including Romania, Iran, the United States, Nigeria, and China.

The probes were uncoordinated, lacked a discernible pattern, and represented the typical ambient scanning that security appliances face daily.

This baseline confirms that the intense, focused activity that followed was a **statistically significant anomaly** and not a general increase in global scanning traffic.


### Phase 2: Coordinated Escalation (13 Aug – 27 Aug 2025)

Around August 13, the nature of the traffic transformed dramatically. Daily events surged from under **1,000** to over **10,000**, culminating in approximately **141,000 hits from 551 unique IPs** over two weeks.

This escalation coincided perfectly with the release of new security advisories for Cisco ASA/FTD vulnerabilities, demonstrating that the campaign's operators were actively monitoring vulnerability disclosures to inform their targeting.

During this phase, the geography of the source IPs shifted from a global, random distribution to a **heavy concentration in IP ranges registered to the Netherlands and Seychelles**.

It was at this point that three specific ASNs emerged as the primary sources of the reconnaissance traffic:

* **AS401116 (NYBULA)**
* **AS401120 (CHEAPY-HOST LLC)**
* **AS215540 (Global Connectivity Solutions LLP)**

The probing methodology also evolved. The random noise of the baseline period was replaced by **methodical, scripted probes** originating from tightly clustered `/24` network ranges.

This shift from chaotic to organized scanning marked the beginning of a **deliberate, campaign-driven operation**.


### Phase 3: The High-Intensity Reconnaissance Wave (28 Aug 2025)

On August 28, the campaign reached its crescendo with a surgical, high-intensity wave of scanning that lasted approximately **20 hours** and generated nearly **200,000 events from 342 unique IP addresses**.

The characteristics of this phase point unequivocally to a centrally managed, automated operation.

* **Timing and Automation**:
  The wave began precisely at 00:00 Australian Eastern Standard Time (AEST) (14:30 UTC on August 27), peaked around 06:00 AEST with **31,233 hits in a single hour**, and tapered off by 21:00 AEST.
  This rigid, 21-hour operational window is inconsistent with opportunistic scanning aligned with regional business hours. Instead, it strongly suggests the execution of a **scheduled batch job** from a central controller, designed to run for a predetermined duration.

* **Uniformity as a Fingerprint**:
  A critical indicator of the campaign's automated nature was its uniformity. Each of the **342 source IP addresses** delivered an almost identical number of requests, approximately **10,102 each**.
  This flat distribution is the calling card of a **scripted, distributed task** where each worker node is assigned an identical workload. It stands in stark contrast to the chaotic, variable traffic patterns of a typical botnet comprised of heterogeneously configured and connected compromised devices.

* **ASN Concentration**:
  The traffic was almost exclusively sourced from the three ASNs identified in Phase 2, confirming their role as the dedicated infrastructure for this operation.
  The breakdown of hits was as follows:

  * **AS401116 – NYBULA**: 70,707 hits
  * **AS401120 – CHEAPY-HOST LLC**: 30,290 hits
  * **AS215540 – Global Connectivity Solutions LLP**: 9,304 hits


### Phase 4: Post-Spike Decline and Analysis

Following the 20-hour wave, traffic volumes dropped precipitously, returning to near-baseline levels.

This rapid cessation of activity confirms that the operation on August 28 was a **time-boxed reconnaissance mission**, not a sustained volumetric attack.

The operators successfully gathered the data they required—likely responses from ASA devices that would allow them to fingerprint software versions and identify vulnerabilities—and subsequently shut down the operation to minimize detection and preserve their infrastructure for future use.


## Strategic Intent: A Pre-Exploitation Playbook

The observed activity was a **classic reconnaissance campaign**, a precursor to exploitation.

The operators were almost certainly mapping the global attack surface of Cisco ASA appliances, cross-referencing their findings against both recent and historical **Common Vulnerabilities and Exposures (CVEs)**.

This "patch-gapping" strategy is common among sophisticated actors, who exploit the window between the announcement of a vulnerability and its widespread remediation by defenders.

By systematically turning public vulnerability data into a private, curated list of vulnerable targets, the attackers have **prepared the battlefield** for follow-on attacks.

Based on the vulnerabilities affecting Cisco ASA devices at the time, the attackers now possess a **menu of exploitation options**:

* **Option A: Denial of Service (Disruption & Extortion)**
  Using vulnerabilities such as **CVE-2025-20182 (IKEv2 DoS)** and **CVE-2025-20134 (SSL/TLS DoS)**, attackers could disrupt VPN services for targeted organizations.
  This capability can be leveraged for extortion demands ("pay us, or your remote access stays down") or used as a diversionary tactic to distract security teams while a more stealthy intrusion occurs elsewhere in the network.

* **Option B: Information Disclosure (Credential & Configuration Theft)**
  For devices identified as running older, unpatched software, attackers can pivot to flaws like **CVE-2024-20353 (SSL VPN configuration leak)** or legacy path traversal bugs like **CVE-2020-3452**.
  Successful exploitation could leak sensitive configuration files containing usernames, group policies, and pre-shared keys (PSKs), providing a direct path to **credential theft** and legitimate, authenticated VPN access.

* **Option C: Remote Code Execution (Full Device Takeover)**
  The oldest and most vulnerable devices discovered during the scan would be susceptible to legacy **Remote Code Execution (RCE)** vulnerabilities, such as **CVE-2020-3452 (WebVPN RCE)** or **CVE-2018-0101 (Smart Install RCE)**.
  A successful RCE attack would grant the adversary **complete control** over the security appliance, establishing a persistent and powerful foothold on the network perimeter.
  From this position, an attacker could conduct lateral movement, exfiltrate data, or deploy ransomware.


## Infrastructure Deconstruction: The Triumvirate of Malicious ASNs

### The Bulletproof Hosting Paradigm

The infrastructure used in this campaign was not composed of incidentally compromised machines but was sourced from a specialized ecosystem of **“bulletproof” hosting (BPH) providers**.

BPH providers are a specific class of internet infrastructure service that knowingly enables malicious actors to host illicit content and run operations online. Unlike legitimate hosts who respond to abuse complaints and law enforcement takedown requests, BPH providers are designed to be **resilient** to such actions.

They achieve this through a combination of:

* **Technical obfuscation** (e.g., fast-flux DNS, routing through proxies)
* **Jurisdictional arbitrage** — operating through opaque corporate structures in regions with lax enforcement or a lack of legal cooperation treaties

BPH providers are **witting participants** in the cybercrime ecosystem, leasing infrastructure for activities ranging from malware C2 and phishing to ransomware operations and botnet control.

The three ASNs central to the Cisco ASA reconnaissance campaign are **textbook examples** of this model.

### AS401116 (NYBULA): The Primary Staging Ground

**AS401116**, operating under the name *NYBULA*, was the **dominant actor** in the peak reconnaissance wave, responsible for over **70,000 hits**.

Its corporate and network profiles are riddled with **red flags characteristic of a BPH provider**.

* **Corporate Profile**:
  The ASN is registered to *Nybula LLC*, an entity with a registered address in Anchorage, Alaska, USA.
  This US registration serves as a veneer of legitimacy, complicating initial legal inquiries from non-US jurisdictions.

* **Network Profile**:
  Despite its US corporate registration, AS401116 announces IP address space allocated by **AFRINIC (the Regional Internet Registry for Africa)** and branded with names like *“internet-security-Nybula”* and associated with the **Seychelles**.
  This deliberate split between the legal jurisdiction of the company (USA) and the administrative region of its network assets (Africa/Seychelles) is a classic BPH tactic designed to create **legal and investigative friction**.

* **Reputation and Malicious Use**:
  The network's reputation is unequivocally malicious.

  * It is listed on the **Spamhaus ASN-DROP list**, a curated list of the internet's most toxic networks. Spamhaus explicitly states that ASNs on this list *“should not be routed or peered with”* as they are *“under control of cyber-criminals.”*
  * The **ThreatFox intelligence platform** has cataloged **668 distinct malware-related Indicators of Compromise (IOCs)** associated with AS401116, confirming its widespread use for distributing malicious payloads.
  * **AbuseIPDB** contains thousands of reports against its IP space for activities including port scanning and unauthorized access attempts.
  * A **Silent Push threat intelligence report** has previously identified NYBULA infrastructure as being part of a **Russian intelligence phishing cluster**, providing a direct link between this ASN and state-aligned threat activity.


### AS401120 (CHEAPY-HOST): The Sibling Network

**AS401120**, registered to *CHEAPY-HOST LLC*, was the **second-largest contributor** to the reconnaissance wave and shares a nearly identical operational profile with NYBULA.

* **Corporate Profile**:
  The operating entity, *cheapy.host LLC*, is registered in Virginia Beach, Virginia, USA.

* **Network Profile**:
  Like NYBULA, it announces **AFRINIC-allocated IP space**, branded as *“internet-security-cheapyhost”* and associated with the Seychelles.

* **Reputation and Malicious Use**:

  * AS401120 is also on the **Spamhaus ASN-DROP list**, marking it as a network controlled by malicious actors.
  * **ThreatFox** has observed **769 malware-related IOCs** within its IP ranges.
  * The ASN was allocated by **ARIN in May 2024**, a very recent registration.
  * This fits the known lifecycle of BPH providers, who frequently establish new ASNs and corporate entities to replace older infrastructure that has been blocked or has garnered too much negative attention.
  * The near-simultaneous creation of **NYBULA (May 30, 2024)** and **CHEAPY-HOST (May 31, 2024)** points not to two independent entities, but to a **single operator deliberately deploying a set of parallel, disposable network assets**.
  * This is further substantiated by their **common upstream provider**.


### The Common Denominator: AS401110 (Sovy Cloud Services)

The critical link between NYBULA and CHEAPY-HOST is their network relationship with **AS401110 (Sovy Cloud Services)**.

Network routing data shows that both AS401116 and AS401120 are **downstream customers of AS401110**, meaning they rely on it for their connectivity to the global internet.

* **Corporate Profile**:
  AS401110 was registered to *Sovy Cloud Services*, a US entity based in Watertown, South Dakota, on **May 29, 2024**—just one day before NYBULA and two days before CHEAPY-HOST.

* **Strategic Importance**:
  This tight timeline is not coincidental; it is **definitive evidence of a pre-planned, coordinated infrastructure deployment** by a single controlling entity.

This structure represents a **sophisticated, modular approach to bulletproof hosting**:

* *Sovy Cloud Services (AS401110)* acts as the **semi-legitimate upstream hub**, maintaining peering relationships with larger providers.
* *NYBULA and CHEAPY-HOST* function as the **disposable, “toxic” front-ends**, designed to absorb abuse complaints and be easily replaced when they are inevitably blocked or burned.

This hierarchical model provides **operational resilience**, as simply blocking the front-end ASNs is insufficient; the threat actor can quickly instantiate new ones under the protection of the parent provider.

**Defenders must recognize** that the core of this threat lies with the **parent entity and its operational model**, not just its current downstream customers.

### ASN Summary Table

| ASN          | Name                          | Registration Entity               | Registration Jurisdiction | IP Space Jurisdiction | Spamhaus ASN-DROP Status | Key Malicious Associations                                       |
| ------------ | ----------------------------- | --------------------------------- | ------------------------- | --------------------- | ------------------------ | ---------------------------------------------------------------- |
| **AS401116** | NYBULA                        | Nybula LLC                        | United States (AK)        | Seychelles (AFRINIC)  | Blocked                  | Russian Intelligence Phishing, Malware Hosting (668+ IOCs)       |
| **AS401120** | CHEAPY-HOST                   | cheapy.host LLC                   | United States (VA)        | Seychelles (AFRINIC)  | Blocked                  | Malware Hosting (769+ IOCs), Port Scanning                       |
| **AS215540** | Global Connectivity Solutions | Global Connectivity Solutions LLP | United Kingdom            | United Kingdom        | Not Listed               | Doppelganger Disinformation, Gamaredon C2, BoneSpy/PlainGnome C2 |


## Unmasking the Operators: A Web of Shells and Cybercriminals

While NYBULA and CHEAPY-HOST rely on a relatively simple (though effective) model of jurisdictional arbitrage, the third network, **AS215540**, reveals a far deeper and more complex web of corporate obfuscation involving offshore shell companies and individuals with extensive histories in both cybercrime and financial malfeasance.


### AS215540 and the Corporate Façade

**AS215540** is operated by *Global Connectivity Solutions LLP*, a Limited Liability Partnership registered in the **United Kingdom** on **January 19, 2024**.

The choice of a UK LLP is a deliberate tactic to project a veneer of legitimacy from a reputable jurisdiction.

However, an examination of its incorporation documents filed with the UK’s *Companies House* reveals a **classic obfuscation strategy** designed to hide the true owners and controllers.

The designated members of the LLP — the legal equivalent of directors — are not individuals. Instead, they are two **corporate entities registered in the Seychelles**, a jurisdiction notorious for its corporate secrecy laws:

* **Lupine Logistics Ltd** (Seychelles Registration No. 215807)
* **LS Trading Partners Inc** (Seychelles Registration No. 215808)

This structure layers offshore anonymity beneath a UK legal framework, making it exceptionally difficult to determine ultimate ownership through conventional means.

However, the UK’s requirement to declare a **“Person with Significant Control” (PSC)** provides the first critical breakthrough.


### Profile: Yevgeniy Valentinovich Marinko (“dimetr50”)

The UK corporate filing for *Global Connectivity Solutions LLP* names **Yevgeniy Valentinovich Marinko**, a Russian national, as the PSC.

The filing asserts that he holds, directly or indirectly, **75% or more of the voting rights** and the right to appoint or remove a majority of the management.

Marinko is not an unknown figure. A comprehensive report by the **Qurium Media Foundation** on the *“Doppelganger”* disinformation campaign explicitly identifies him, along with his common aliases *“dimetr50”* and *“Rustam Yangirov”*, as the operator of both *Global Connectivity Solutions LLP (AS215540)* and a precursor company, *Global Internet Solutions LLC (GIR)*.

Marinko’s history is rooted in **financially motivated cybercrime**:

* The Qurium report documents his operation of an online shop, **shopsn.su**, which was used to trade stolen credentials.
* He ran this operation in partnership with **Igor Dekhtyarchuk**, a Russian hacker known by the alias *“Floraby”*.
* This connection is independently corroborated by the **U.S. Federal Bureau of Investigation (FBI)**, which placed Dekhtyarchuk on its *“Cyber’s Most Wanted”* list in March 2022 for operating a cybercriminal marketplace that sold thousands of stolen login credentials and other sensitive data.
* Further evidence of Marinko’s criminal activities includes a **fine in Sevastopol for malware-related fraud**.


### Profile: Kirils Pestuns and the “Company Formation Factory”

While Marinko is the declared operational controller, the trail of ownership for the Seychelles entities leads to another key figure in the world of financial crime facilitation: **Kirils Pestuns**, a Latvian national.

The **Pandora Papers** identify Pestuns as the beneficial owner of both **Lupine Logistics Ltd** and **LS Trading Partners Inc**.

Pestuns is the founder of **ComForm Solutions**, a UK-based company formation agency that specializes in creating low-cost, anonymous UK corporate entities, particularly for clients from the former Soviet Union.

Investigations have tied Pestuns’ entities to major laundering scandals:

* The **International Consortium of Investigative Journalists (ICIJ)**, via the *FinCEN Files*, revealed that at least **380 UK companies created or administered by ComForm** were flagged in connection with potential money laundering.
* Companies established by Pestuns’ agency were identified as core components of the *“Russian Laundromat”*, a massive scheme that funneled over **\$20 billion in illicit funds** out of Russia.

The relationship between Marinko and Pestuns exemplifies a **specialized division of labor** within a sophisticated criminal support ecosystem:

* **Pestuns**: expert in creating the opaque corporate structures needed to hide ownership and frustrate legal investigations — the *corporate layer*.
* **Marinko**: technical operator who requires these anonymous entities to register network assets and run malicious infrastructure — the *technical layer*.

This symbiotic partnership demonstrates a **mature and resilient model** for enabling a wide range of illicit online activities.

### Operator Role Table

| Role                                          | Entity / Individual Name          | Entity Type / Nationality                   | Jurisdiction   | Key Details                                                             |
| --------------------------------------------- | --------------------------------- | ------------------------------------------- | -------------- | ----------------------------------------------------------------------- |
| **Operating ASN**                             | AS215540                          | Autonomous System                           | United Kingdom | Used for Cisco ASA recon; hosts malicious services                      |
| **Legal Entity**                              | Global Connectivity Solutions LLP | Limited Liability Partnership               | United Kingdom | UK corporate front for the ASN                                          |
| **Person with Significant Control**           | Yevgeniy Valentinovich Marinko    | Russian National                            | Russia         | Declared controller; known cybercriminal (“dimetr50”)                   |
| **Designated Member**                         | Lupine Logistics Ltd              | International Business Company (Seychelles) | Seychelles     | Corporate member of the UK LLP                                          |
| **Designated Member**                         | LS Trading Partners Inc           | International Business Company (Seychelles) | Seychelles     | Corporate member of the UK LLP                                          |
| **Beneficial Owner (of Seychelles entities)** | Kirils Pestuns                    | Latvian National                            | Latvia / UK    | Runs ComForm Solutions, linked to *FinCEN Files* & *Russian Laundromat* |


## Attribution and Campaign Linkages: Connecting the Dots

The infrastructure operated by this network of individuals and shell companies is not merely a platform for opportunistic cybercrime. It is a **key enabler** for a spectrum of malicious activities, including state-aligned espionage and persistent information warfare campaigns.

The evidence demonstrates a clear **convergence of financially motivated crime and Russian state interests** operating on this shared, wittingly-provided infrastructure.


### The Doppelganger Disinformation Nexus

The most direct link between this infrastructure and state-aligned activity comes from the **Qurium report**, which identifies Marinko’s companies — *Global Connectivity Solutions LLP (AS215540)* and *Global Internet Solutions LLC (GIR, AS207713)* — as **core components** of the hosting infrastructure for the *“Doppelganger”* disinformation campaign.

**Doppelganger** is a long-running and sophisticated pro-Kremlin influence operation. Its primary tactic is to create high-fidelity **clones of legitimate news outlets** (such as *The Guardian* and *Le Monde*) and government websites (including the French Ministry of Foreign Affairs and NATO) on **typosquatted domains**.

These fake sites are then used to publish fabricated articles and forged documents that promote narratives aligned with Russian state interests, such as:

* undermining Western support for Ukraine
* fomenting social division
* discrediting international institutions

The use of Marinko’s **bulletproof hosting network** is critical to the campaign’s resilience, allowing the disinformation sites to remain online despite efforts by platforms and governments to block them.


### A Hub for Russian-Aligned Cybercrime and Espionage

Beyond disinformation, the infrastructure has a documented history of hosting **command-and-control (C2) servers** for Russian-aligned Advanced Persistent Threat (APT) groups engaged in cyber espionage:

* **Gamaredon (aka Primitive Bear, Shuckworm)**

  * Widely attributed to Russia’s Federal Security Service (FSB)
  * Used Marinko’s infrastructure to operate **C2 servers for its Android surveillanceware**
  * Known for persistent targeting of Ukrainian government and military entities

* **BoneSpy and PlainGnome**

  * Two families of Android surveillanceware linked to Russian-nexus espionage
  * Target individuals in former Soviet states
  * Hosted on the same network infrastructure

This pattern of supporting state-aligned actors is **not limited** to AS215540.

A separate **Silent Push threat intelligence report** identified **NYBULA (AS401116)** as being used by a **Russian intelligence phishing cluster**, demonstrating that the newer infrastructure controlled by the same operators continues to serve similar clients.


### The Broader Ecosystem: Connections to Aeza Group

The Qurium report also notes that the broader *Doppelganger* campaign has its **“hub”** in infrastructure provided by **Aeza Group**, another notorious Russian bulletproof hosting provider.

In July 2025, the **U.S. Department of the Treasury** sanctioned Aeza Group for providing services to:

* numerous ransomware gangs (*including BianLian*)
* infostealer operators (*Lumma, Meduza*)
* the **BlackSprut darknet drug market**

This connection places Marinko’s operations squarely within the same ecosystem of Russian BPH providers known to facilitate both high-end cybercrime and state-directed campaigns.

These are not isolated actors but rather **interconnected nodes** in a larger, resilient network that serves a common set of malicious interests.

The co-location of:

* financially motivated criminal tools (credential theft marketplaces)
* state-sponsored espionage C2 (Gamaredon)
* state-aligned influence operations (Doppelganger)

…on infrastructure controlled by the same individuals is the **most critical strategic finding** of this analysis.

It demonstrates a **symbiotic, and likely state-condoned, relationship** between Russian intelligence services and the Russian cybercrime underworld.

This is not a case of a state actor incidentally compromising a criminal’s server; it is a case of a **criminal’s purpose-built infrastructure being a witting and core component of state operations**.

For defenders, this means that an attack vector that appears purely criminal in nature could be a precursor to, or have a direct nexus with, **espionage or information warfare**.


### Associated Infrastructure Table

| ASN / Company                          | Threat / Campaign Name        | Threat Type                          | Attributed Actor / Group                                     | Source of Attribution             |
| -------------------------------------- | ----------------------------- | ------------------------------------ | ------------------------------------------------------------ | --------------------------------- |
| AS215540 (GCS LLP), AS207713 (GIR LLC) | Doppelganger                  | Disinformation / Influence Operation | Pro-Kremlin / Russian-aligned                                | Qurium Media Foundation           |
| AS215540 (GCS LLP)                     | Gamaredon C2                  | Espionage (Android Surveillanceware) | Gamaredon (Primitive Bear / FSB-linked)                      | Honeypot Report                   |
| AS215540 (GCS LLP)                     | BoneSpy / PlainGnome C2       | Espionage (Android Surveillanceware) | Russian-aligned                                              | Honeypot Report, CYFIRMA          |
| AS401116 (NYBULA)                      | Phishing Cluster              | Espionage (Phishing)                 | Russian Intelligence                                         | Silent Push (via Honeypot Report) |
| AS215540 (GCS LLP), AS207713 (GIR LLC) | Stolen Credential Marketplace | Cybercrime                           | Yevgeniy Marinko (“dimetr50”), Igor Dekhtyarchuk (“Floraby”) | Qurium Media Foundation, FBI      |


## Strategic Implications and Threat Actor Modus Operandi

### The Bulletproof Hoster’s Playbook

The collective activity and infrastructure attributes analyzed in this report reveal a sophisticated and repeatable **modus operandi** for establishing and operating a resilient, multi-purpose malicious hosting ecosystem.

This playbook can be broken down into **four distinct phases**:

1. **Corporate Obfuscation**
   The operation begins not with servers, but with paperwork.

   * The actors engage specialists in corporate secrecy, such as **Kirils Pestuns’ ComForm Solutions**, to construct a layered and legally ambiguous corporate structure.
   * The preferred model involves a **UK-registered entity (LLP)** for a veneer of legitimacy, with ownership and control vested in shell companies located in secrecy havens like the **Seychelles**.
   * This immediately builds in **legal and jurisdictional friction** for investigators.

2. **Modular Infrastructure Deployment**
   With an anonymous corporate vehicle in place, the operators register a **cluster of ASNs**.

   * A modular, hierarchical structure is preferred, with a **semi-clean parent ASN** (e.g., Sovy Cloud Services) providing transit for multiple disposable, “toxic” child ASNs (e.g., NYBULA, CHEAPY-HOST).
   * This design allows the front-end networks to be **burned and replaced** without disrupting the core upstream connectivity.
   * Jurisdictional arbitrage is employed at the network level, using **IP address space from one region (e.g., Africa)** for an entity registered in another (e.g., USA), with servers physically located in a third (e.g., Europe).

3. **Reconnaissance-as-a-Service**
   The infrastructure is leveraged to conduct large-scale, automated reconnaissance campaigns.

   * These are often timed to coincide with **major software vulnerability disclosures**, allowing the operators to systematically map the global attack surface for a specific flaw.
   * The resulting data — a curated list of vulnerable targets — is a **valuable commodity in itself**.

4. **Monetization and Exploitation**
   The infrastructure and the intelligence gathered from reconnaissance are provided to a **diverse clientele**:

   * financially motivated cybercriminals (for malware distribution and phishing)
   * state-sponsored espionage groups (for C2 infrastructure)
   * state-aligned information warfare campaigns (for resilient hosting of disinformation content)


### The Convergence of Threats

A key strategic implication of this analysis is the demonstrated **convergence of threats** that were once analyzed in separate silos.

The infrastructure controlled by Marinko and his associates is a **shared resource** for:

* cybercrime
* cyber espionage
* influence operations

This blending of motives and activities presents a **significant challenge** for defenders.

An initial intrusion that appears to be **standard crimeware** (e.g., an infostealer infection) could be a precursor to an **espionage-motivated attack** — or the credentials stolen could be used to facilitate a **disinformation campaign**.

Security teams can no longer afford to assess threats based on a **single, assumed motive**. The infrastructure itself must be seen as a **holistic threat**, regardless of the specific malicious payload it delivers at any given moment.


### The Lifecycle of Malicious Infrastructure

The recent registration of the **NYBULA, CHEAPY-HOST, and Sovy Cloud Services ASNs in May 2024** is indicative of the **ephemeral lifecycle** of this type of infrastructure.

BPH operators assume their assets will eventually be **identified, analyzed, and blocked** by the security community.

Their model is built on the ability to:

* rapidly **abandon burned assets**
* reconstitute their operations on **freshly registered networks and corporate shells**

This highlights the **limitations of a purely reactive, indicator-based defense**.

While blocking the currently known malicious ASNs is a necessary tactical step, a more strategic approach requires **tracking the operators, their TTPs, and their enablers** (like company formation services) to anticipate and potentially disrupt the creation of the **next generation of their infrastructure**.


## Actionable Intelligence and Recommendations for Defenders

### Tactical Mitigations

* **Block Malicious ASNs**
  Network defenders should immediately add **AS401116 (NYBULA)**, **AS401120 (CHEAPY-HOST)**, and **AS215540 (Global Connectivity Solutions LLP)** to network blocklists at the edge firewall or via BGP routing policy.
  Traffic to or from these networks should be considered **inherently hostile**.

* **Monitor Upstream Providers**
  The parent provider, **AS401110 (Sovy Cloud Services)**, should be placed on a **high-priority watchlist**.
  While not directly observed in the malicious scanning, it is the **key enabler** for the toxic downstream networks. Monitoring this ASN for the announcement of new downstream peers can provide **early warning** of the next iteration of this actor's infrastructure.

* **Proactive Threat Hunting**
  Security teams should proactively hunt for signs of this campaign in their own environments using the following logic, adaptable to various SIEM platforms. The provided **KQL queries** serve as a template:

  * *Hunt for Activity from Hostile ASNs*:

    ```kql
    geoip.asn: (401116 or 401120 or 215540)
    ```

  * *Hunt for Cisco ASA-Specific Probes*:

    ```kql
    geoip.asn: (401116 or 401120 or 215540) 
    and destination.port: (443 or 8443) 
    and payload_printable: ("GET /+CSCOE+/" or "POST /+webvpn+/")
    ```

  * *Hunt for IKEv2 Sweeps*:

    ```kql
    geoip.asn: (401116 or 401120 or 215540) 
    and network.transport: udp 
    and destination.port: (500 or 4500)
    ```


### Strategic Defense Posture

* **Prioritize Vulnerability Management for Edge Devices**
  This campaign underscores that **internet-facing security appliances** (firewalls, VPN concentrators) are **primary targets** for mass reconnaissance.
  Organizations must have an **aggressive and rapid patching process** for these critical devices, as threat actors are actively weaponizing vulnerability disclosures within **days or even hours**.

* **Adopt a Policy on Abuse-Tolerant Infrastructure**
  Organizations should move beyond reacting to **individual bad IPs** and adopt a broader policy of treating traffic from any ASN listed on reputable, professionally maintained blocklists (such as the **Spamhaus ASN-DROP list**) as **hostile by default**.
  The risk of blocking legitimate traffic from these networks is negligible compared to the risk of allowing communication with infrastructure that is demonstrably controlled by cybercriminals.

* **Integrate Non-Traditional Threat Intelligence**
  The unmasking of the operators behind **AS215540** was not possible through network data alone.
  It required correlating technical indicators with:

  * corporate registration data (*UK Companies House*)
  * investigative journalism (*ICIJ’s FinCEN Files analysis*)
  * specialized reports (*Qurium*)

  Security programs should seek to integrate these **non-traditional OSINT sources**.

  Tracking known malicious *“company formation agents”* like **Kirils Pestuns** and the corporate vehicles they create can provide **high-fidelity early warnings** of infrastructure that will almost certainly be used for malicious purposes in the future.


## Works Cited

1. “Bulletproof” hosting providers | Cyber.gov.au, accessed on August 30, 2025, [https://www.cyber.gov.au/about-us/view-all-content/publications/bulletproof-hosting-providers](https://www.cyber.gov.au/about-us/view-all-content/publications/bulletproof-hosting-providers)
2. *Bulletproof hosting* - Wikipedia, accessed on August 30, 2025, [https://en.wikipedia.org/wiki/Bulletproof\_hosting](https://en.wikipedia.org/wiki/Bulletproof_hosting)
3. Inside the Bulletproof Hosting Business: Cybercriminal Methods and OpSec - Trend Micro, accessed on August 30, 2025, [https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/inside-the-bulletproof-hosting-business-cybercrime-methods-opsec](https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/inside-the-bulletproof-hosting-business-cybercrime-methods-opsec)
4. What is Bulletproof Hosting? | Methods, Examples & More - Bolster AI, accessed on August 30, 2025, [https://bolster.ai/glossary/what-is-bulletproof-hosting](https://bolster.ai/glossary/what-is-bulletproof-hosting)
5. AS401116 Nybula LLC - bgp.tools, accessed on August 30, 2025, [https://bgp.tools/as/401116](https://bgp.tools/as/401116)
6. AS401116 Nybula LLC details - Ipregistry, accessed on August 30, 2025, [https://ipregistry.co/AS401116](https://ipregistry.co/AS401116)
7. ThreatFox ASN report for AS401116, accessed on August 30, 2025, [https://threatfox.abuse.ch/asn/401116/](https://threatfox.abuse.ch/asn/401116/)
8. 196.251.117.97 | internet-security-Nybula | AbuseIPDB, accessed on August 30, 2025, [https://www.abuseipdb.com/check/196.251.117.97?page=31](https://www.abuseipdb.com/check/196.251.117.97?page=31)
9. AbuseIPDB » 196.251.117.216 - internet-security-Nybula, accessed on August 30, 2025, [https://www.abuseipdb.com/check/196.251.117.216](https://www.abuseipdb.com/check/196.251.117.216)
10. AS401120 cheapy.host LLC - bgp.tools, accessed on August 30, 2025, [https://bgp.tools/as/401120](https://bgp.tools/as/401120)
11. ASN Information for 401120 Cheapy.host LLC - IP2Location, accessed on August 30, 2025, [https://www.ip2location.com/as401120](https://www.ip2location.com/as401120)
12. AS401120 cheapy.host LLC BGP Network Information - BGPView, accessed on August 30, 2025, [https://bgpview.io/asn/401120](https://bgpview.io/asn/401120)
13. ThreatFox ASN report for AS401120 - Abuse.ch, accessed on August 30, 2025, [https://threatfox.abuse.ch/asn/401120/](https://threatfox.abuse.ch/asn/401120/)
14. AS401116 - Whois-RWS, accessed on August 30, 2025, [https://whois.arin.net/rest/asn/AS401116](https://whois.arin.net/rest/asn/AS401116)
15. AS401110 Sovy Cloud Services details - IPinfo.io, accessed on August 30, 2025, [https://ipinfo.io/AS401110](https://ipinfo.io/AS401110)
16. AS401110 Sovy Cloud Services - BGP.Tools, accessed on August 30, 2025, [https://bgp.tools/as/401110](https://bgp.tools/as/401110)
17. AS215540 Global Connectivity Solutions LLP - IP2Location, accessed on August 30, 2025, [https://www.ip2location.com/as215540](https://www.ip2location.com/as215540)
18. How Russia uses EU companies for propaganda – Qurium Media Foundation, accessed on August 30, 2025, [https://www.qurium.org/alerts/exposing-the-evil-empire-of-doppelganger-disinformation/](https://www.qurium.org/alerts/exposing-the-evil-empire-of-doppelganger-disinformation/)
19. AS215540 GLOBAL CONNECTIVITY SOLUTIONS LLP - BGP.Tools, accessed on August 30, 2025, [https://bgp.tools/as/215540](https://bgp.tools/as/215540)
20. AS215540 GLOBAL CONNECTIVITY SOLUTIONS LLP - bgp.he.net, accessed on August 30, 2025, [https://bgp.he.net/AS215540](https://bgp.he.net/AS215540)
21. companies\_house\_document (1).pdf
22. LUPINE LOGISTICS LTD personal appointments - Find and update company information, accessed on August 30, 2025, [https://find-and-update.company-information.service.gov.uk/officers/qVvi20NIhZfCSrhCS2aX1aal4Ug/appointments](https://find-and-update.company-information.service.gov.uk/officers/qVvi20NIhZfCSrhCS2aX1aal4Ug/appointments)
23. LUPINE LOGISTICS LTD, 215807 - Kombo.lv, accessed on August 30, 2025, [https://www.kombo.lv/en/foreign-profile/089a758a1ed9e08ed25b912e67/lupine-logistics-ltd](https://www.kombo.lv/en/foreign-profile/089a758a1ed9e08ed25b912e67/lupine-logistics-ltd)
24. LS TRADING PARTNERS INC, 215808 - Kombo.lv, accessed on August 30, 2025, [https://www.kombo.lv/en/foreign-profile/e1b42ea021e1f7c21b32a2b62b/ls-trading-partners-inc](https://www.kombo.lv/en/foreign-profile/e1b42ea021e1f7c21b32a2b62b/ls-trading-partners-inc)
25. LS TRADING PARTNERS INC personal appointments - GOV.UK, accessed on August 30, 2025, [https://find-and-update.company-information.service.gov.uk/officers/UM1570TiKx9WMA9cxZTs5Vpj4uw/appointments](https://find-and-update.company-information.service.gov.uk/officers/UM1570TiKx9WMA9cxZTs5Vpj4uw/appointments)
26. Igor Dekhtyarchuk - FBI, accessed on August 30, 2025, [https://www.fbi.gov/wanted/cyber/igor-dekhtyarchuk/download.pdf](https://www.fbi.gov/wanted/cyber/igor-dekhtyarchuk/download.pdf)
27. IGOR DEKHTYARCHUK - FBI, accessed on August 30, 2025, [https://www.fbi.gov/wanted/cyber/igor-dekhtyarchuk](https://www.fbi.gov/wanted/cyber/igor-dekhtyarchuk)
28. Russian National Indicted in East Texas for Cyber Hacking Enterprise, accessed on August 30, 2025, [https://www.justice.gov/usao-edtx/pr/russian-national-indicted-east-texas-cyber-hacking-enterprise](https://www.justice.gov/usao-edtx/pr/russian-national-indicted-east-texas-cyber-hacking-enterprise)
29. More Re\:Baltica revelations show Latvian involvement in UK company formation schemes, accessed on August 30, 2025, [https://eng.lsm.lv/article/economy/banks/more-rebaltica-revelations-show-latvian-involvement-in-uk-company-formation-schemes.a375360/](https://eng.lsm.lv/article/economy/banks/more-rebaltica-revelations-show-latvian-involvement-in-uk-company-formation-schemes.a375360/)
30. Meet the old school friends running a UK formation agency linked to the Russian laundromat scandal - Finance Uncovered, accessed on August 30, 2025, [https://www.financeuncovered.org/stories/english-limited-partnerships-comform-company-formation-agencies](https://www.financeuncovered.org/stories/english-limited-partnerships-comform-company-formation-agencies)
31. What is the Doppelganger operation? List of resources - EU DisinfoLab, accessed on August 30, 2025, [https://www.disinfo.eu/doppelganger-operation/](https://www.disinfo.eu/doppelganger-operation/)
32. Russian Disinformation Campaign “DoppelGänger” Unmasked: A Web of Deception, accessed on August 30, 2025, [https://www.cybercom.mil/Media/News/Article/3895345/russian-disinformation-campaign-doppelgnger-unmasked-a-web-of-deception/](https://www.cybercom.mil/Media/News/Article/3895345/russian-disinformation-campaign-doppelgnger-unmasked-a-web-of-deception/)
33. Weekly Intelligence Report - 20 Dec 2024 - CYFIRMA, accessed on August 30, 2025, [https://www.cyfirma.com/news/weekly-intelligence-report-20-dec-2024/](https://www.cyfirma.com/news/weekly-intelligence-report-20-dec-2024/)
34. Disinformation, Malware and Drugs: Aeza's cyber crime portfolio - Qurium, accessed on August 30, 2025, [https://www.qurium.org/press-releases/aeza-disinformation-and-drugs/](https://www.qurium.org/press-releases/aeza-disinformation-and-drugs/)
35. Treasury Sanctions Global Bulletproof Hosting Service Enabling Cybercriminals and Technology Theft, accessed on August 30, 2025, [https://home.treasury.gov/news/press-releases/sb0185](https://home.treasury.gov/news/press-releases/sb0185)
36. Russian bulletproof hosting service Aeza Group sanctioned by US for ransomware work, accessed on August 30, 2025, [https://therecord.media/russia-bulletproof-hosting-aeza-group-us-sanctions](https://therecord.media/russia-bulletproof-hosting-aeza-group-us-sanctions)
37. US sanctions bulletproof hosting provider for supporting ransomware, infostealer operations, accessed on August 30, 2025, [https://cyberscoop.com/bulletproof-hosting-provider-aezagroup-sanctions/](https://cyberscoop.com/bulletproof-hosting-provider-aezagroup-sanctions/)
