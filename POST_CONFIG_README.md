# SOC Trend Micro Vision One – Product Enhancement Configuration

This repository contains configuration assets and playbooks that enhance the **Trend Micro Vision One** integration within Cortex XSIAM.  
These enhancements improve visibility, triage workflows, and automation by aligning Vision One alerts to the SOC Framework and MITRE ATT&CK tactics.

---

## 📌 Overview

Trend Micro Vision One provides advanced XDR telemetry across endpoint, email, network, and identity sources.  
However, its alerts often require normalization, field mapping, and correlation to fully align with XSIAM workflows.

This enhancement package enables:

- A custom layout rule for Vision One alerts
- MITRE tactic–aligned correlation rules for early incident grouping
- A fallback correlation rule for unmapped or generic alerts

---

## 🚀 Getting Started

### Step 1: Create a Layout Rule for Vision One Alerts

To improve analyst efficiency and ensure consistent presentation of Vision One data:

Go To: **Settings → Configurations → Object Setup → Layout Rules**

- **Rule Name:** `Trend Micro Vision One Alert Layout`
- **Entity Type:** Alert
- **Filter Criteria:**
  - Alert Source: Equals `Trend Micro Vision One`
- **Action:**
  - Assign a custom alert layout optimized for Vision One alert data

> This layout should surface key fields such as `Alert ID`, `Severity`, `Category`, `Host`, `User`, and `Detection Time`.

#### 🖼️ Layout Rule Visualization

![Vision One Layout Rules](images/TrendVisionOneLayout.png)

> This rule ensures that analysts immediately see the most relevant Vision One alert data in context.

---

### Step 2: Enable MITRE Tactic–Based Correlation Rules

Enable correlation rules that group Vision One alerts into incidents based on their mapped MITRE ATT&CK tactic.

Go To: **Detection & Correlation → Correlation Rules**

Enable the following rules:

![Vision One Layout Rules](images/TrendVisionCorrelations.png)

#### 🖼️ Correlation Rules Visualization

![Trend Micro Vision One Correlation Rules](https://github.com/Palo-Cortex/images/TrendVisionCorrelations.png)

> Vision One alerts are organized by MITRE tactic to streamline triage and incident response.

---

### Step 3: Enable No MITRE Tactic Correlation Rule

Some Vision One alerts may not include a MITRE mapping. Enable the fallback rule to ensure these are still grouped efficiently.

- **Rule Name:** `Trend Micro Vision One – No MITRE Tactic`
- **Logic:**
  - `tactic` is null or missing
  - Group by fields such as `Alert ID`, `Host`, or `User`

> This ensures all alerts, even those without a defined tactic, are grouped for triage and analysis.

---

## 🧠 Why This Matters

These configurations align directly with the **XSIAM FieldOps Model** and **SOC Optimization Framework**, delivering:

| Value Driver          | Capability Delivered                                              |
|------------------------|-------------------------------------------------------------------|
| Transformation         | Consistent, enriched layouts for all Vision One alerts            |
| Risk & Resiliency      | MITRE mapping improves visibility and detection coverage          |
| Automation & Efficacy  | Correlation reduces alert fatigue and improves investigation speed |

---

## 🧪 Validation Tips

- Simulate Vision One alerts across multiple tactics to validate correlation rules
- Confirm the custom layout applies only to Vision One alerts
- Check incident grouping logic under **Incidents → Recent Activity**
- Review dashboards such as **SOC Value Metrics** and **Vision One Overview** for populated metrics

## 🧩 Dependencies

- Custom Alert Layout (JSON layout file included in pack)
- SOC Optimization Framework (for scoring, enrichment, and triage workflows)
- SOC Common Playbooks (for enrichment and normalization consistency)

---

For questions or help extending this pack, contact your **Palo Alto Networks Field Team** or the **SOC Framework maintainers**.
