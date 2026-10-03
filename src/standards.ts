import type { StandardReference } from "./contracts.js";

export const STANDARD_VERSIONS = {
  nistSsdf: "1.1",
  owaspAsvs: "5.0.0",
  owaspWstg: "4.2",
  owaspSamm: "2.2.0",
  mitreCwe: "4.20",
} as const;

export function reference(
  standard: StandardReference["standard"],
  version: string,
  control: string,
): StandardReference {
  return { standard, version, control };
}

export const refs = {
  cwe: (control: string) => reference("mitre-cwe", STANDARD_VERSIONS.mitreCwe, control),
  ssdf: (control: string) => reference("nist-ssdf", STANDARD_VERSIONS.nistSsdf, control),
  asvs: (control: string) => reference("owasp-asvs", STANDARD_VERSIONS.owaspAsvs, control),
  wstg: (control: string) => reference("owasp-wstg", STANDARD_VERSIONS.owaspWstg, control),
  samm: (control: string) => reference("owasp-samm", STANDARD_VERSIONS.owaspSamm, control),
};
