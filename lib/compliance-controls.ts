export type ComplianceControl = {
  id: string;
  title: string;
};

export type ComplianceFramework = {
  id: "hipaa" | "pci-dss" | "fedramp" | "soc2" | "iso27001" | "nist-csf";
  label: string;
  shortLabel: string;
  version: string;
  controls: ComplianceControl[];
};

export const complianceFrameworks: ComplianceFramework[] = [
  {
    id: "hipaa",
    label: "HIPAA Security Rule",
    shortLabel: "HIPAA",
    version: "45 CFR Part 164",
    controls: [
      { id: "164.308(a)(1)", title: "Security management process" },
      { id: "164.308(a)(3)", title: "Workforce security" },
      { id: "164.308(a)(4)", title: "Information access management" },
      { id: "164.308(a)(5)", title: "Security awareness and training" },
      { id: "164.308(a)(6)", title: "Security incident procedures" },
      { id: "164.308(a)(7)", title: "Contingency plan" },
      { id: "164.308(a)(8)", title: "Evaluation" },
      { id: "164.310(a)(1)", title: "Facility access controls" },
      { id: "164.310(b)", title: "Workstation use" },
      { id: "164.310(c)", title: "Workstation security" },
      { id: "164.310(d)(1)", title: "Device and media controls" },
      { id: "164.312(a)(1)", title: "Access control" },
      { id: "164.312(b)", title: "Audit controls" },
      { id: "164.312(c)(1)", title: "Integrity" },
      { id: "164.312(d)", title: "Person or entity authentication" },
      { id: "164.312(e)(1)", title: "Transmission security" },
      { id: "164.316(b)(1)", title: "Documentation" },
    ],
  },
  {
    id: "pci-dss",
    label: "PCI DSS",
    shortLabel: "PCI DSS",
    version: "v4.0.1",
    controls: [
      { id: "1.2.1", title: "Network security control configuration standards" },
      { id: "2.2.1", title: "System component configuration standards" },
      { id: "3.4.1", title: "Primary account number rendering" },
      { id: "4.2.1", title: "Strong cryptography for transmission" },
      { id: "5.2.1", title: "Anti-malware mechanisms" },
      { id: "6.3.3", title: "Security patches and updates" },
      { id: "6.4.3", title: "Payment page script management" },
      { id: "7.2.1", title: "Access control model" },
      { id: "8.3.1", title: "Strong authentication" },
      { id: "9.2.1", title: "Physical access controls" },
      { id: "10.2.1", title: "Audit log enablement" },
      { id: "11.3.1", title: "Internal vulnerability scans" },
      { id: "11.6.1", title: "Change and tamper detection" },
      { id: "12.3.1", title: "Targeted risk analysis" },
    ],
  },
  {
    id: "fedramp",
    label: "FedRAMP Rev. 5",
    shortLabel: "FedRAMP",
    version: "NIST SP 800-53 Rev. 5",
    controls: [
      { id: "AC-2", title: "Account management" },
      { id: "AC-3", title: "Access enforcement" },
      { id: "AC-6", title: "Least privilege" },
      { id: "AU-2", title: "Event logging" },
      { id: "AU-6", title: "Audit record review, analysis, and reporting" },
      { id: "CA-7", title: "Continuous monitoring" },
      { id: "CM-2", title: "Baseline configuration" },
      { id: "CM-6", title: "Configuration settings" },
      { id: "CP-9", title: "System backup" },
      { id: "IA-2", title: "Identification and authentication" },
      { id: "IR-4", title: "Incident handling" },
      { id: "RA-5", title: "Vulnerability monitoring and scanning" },
      { id: "SC-7", title: "Boundary protection" },
      { id: "SC-12", title: "Cryptographic key establishment and management" },
      { id: "SI-2", title: "Flaw remediation" },
      { id: "SI-4", title: "System monitoring" },
    ],
  },
  {
    id: "soc2",
    label: "SOC 2 Trust Services Criteria",
    shortLabel: "SOC 2",
    version: "2017 TSC with revised points of focus",
    controls: [
      { id: "CC1.1", title: "Integrity and ethical values" },
      { id: "CC2.1", title: "Quality information" },
      { id: "CC3.2", title: "Risk identification and analysis" },
      { id: "CC5.2", title: "Technology control activities" },
      { id: "CC6.1", title: "Logical and physical access controls" },
      { id: "CC6.6", title: "System boundary protections" },
      { id: "CC6.7", title: "Data transmission and movement" },
      { id: "CC7.2", title: "System monitoring" },
      { id: "CC7.3", title: "Security event evaluation" },
      { id: "CC8.1", title: "Change management" },
      { id: "A1.2", title: "Environmental protections and recovery" },
      { id: "C1.1", title: "Confidential information protection" },
    ],
  },
  {
    id: "iso27001",
    label: "ISO/IEC 27001",
    shortLabel: "ISO 27001",
    version: "2022 Annex A",
    controls: [
      { id: "A.5.15", title: "Access control" },
      { id: "A.5.16", title: "Identity management" },
      { id: "A.5.17", title: "Authentication information" },
      { id: "A.5.18", title: "Access rights" },
      { id: "A.5.23", title: "Information security for cloud services" },
      { id: "A.5.24", title: "Incident management planning" },
      { id: "A.5.28", title: "Collection of evidence" },
      { id: "A.8.2", title: "Privileged access rights" },
      { id: "A.8.5", title: "Secure authentication" },
      { id: "A.8.9", title: "Configuration management" },
      { id: "A.8.12", title: "Data leakage prevention" },
      { id: "A.8.15", title: "Logging" },
      { id: "A.8.16", title: "Monitoring activities" },
      { id: "A.8.20", title: "Network security" },
      { id: "A.8.24", title: "Use of cryptography" },
    ],
  },
  {
    id: "nist-csf",
    label: "NIST Cybersecurity Framework",
    shortLabel: "NIST CSF",
    version: "2.0",
    controls: [
      { id: "GV.OC", title: "Organizational context" },
      { id: "GV.RM", title: "Risk management strategy" },
      { id: "GV.SC", title: "Cybersecurity supply chain risk management" },
      { id: "ID.AM", title: "Asset management" },
      { id: "ID.RA", title: "Risk assessment" },
      { id: "PR.AA", title: "Identity management, authentication, and access control" },
      { id: "PR.DS", title: "Data security" },
      { id: "PR.PS", title: "Platform security" },
      { id: "DE.CM", title: "Continuous monitoring" },
      { id: "DE.AE", title: "Adverse event analysis" },
      { id: "RS.MA", title: "Incident management" },
      { id: "RC.RP", title: "Recovery plan execution" },
    ],
  },
];

export type ComplianceFrameworkId = ComplianceFramework["id"];

export function frameworkById(id: string): ComplianceFramework | null {
  return complianceFrameworks.find((framework) => framework.id === id) ?? null;
}

export function controlById(frameworkId: string, controlId: string): ComplianceControl | null {
  return frameworkById(frameworkId)?.controls.find((control) => control.id === controlId) ?? null;
}

export function safeNameSegment(value: string, fallback = "evidence"): string {
  const normalized = value.normalize("NFKD").replace(/[\u0300-\u036f]/g, "");
  const safe = normalized.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").replace(/-{2,}/g, "-");
  return (safe || fallback).slice(0, 80);
}

export function controlFolderSegment(controlId: string): string {
  return safeNameSegment(controlId.replace(/[()]/g, "-"), "unmapped-control").toLowerCase();
}

export function screenshotFilename(input: {
  frameworkId: string;
  controlId: string;
  customName: string;
  capturedAt: string;
}): string {
  const framework = frameworkById(input.frameworkId);
  const prefix = safeNameSegment(framework?.shortLabel ?? input.frameworkId).toUpperCase();
  const control = controlFolderSegment(input.controlId);
  const timestamp = new Date(input.capturedAt).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
  return `${prefix}_${control}_${timestamp}_${safeNameSegment(input.customName)}.png`;
}
