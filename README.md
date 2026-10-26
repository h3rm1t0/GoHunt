# GoHunt

<img width="641" height="226" alt="Captura de tela de 2026-10-20 11-20-42" src="https://github.com/user-attachments/assets/87495a07-9f34-432b-a7c3-580ce095c2a8" />


A tool developed in Go for reconnaissance and triage in bug bounty programs and authorized security assessments. Its purpose is to organize the discovered attack surface, reduce duplicate results, and support manual validation with traceable evidence.

Developed by **h3rm1t0** as an independent research and software engineering project focused on security.

## Features

- **Explicit scope definition:** Domains, subdomains, and URLs, with hostname-based authorization controls.
- **Public reconnaissance:** Integration with crt.sh, AlienVault OTX, Wayback Machine, and Common Crawl.
- **Web crawling:** Light, balanced, and deep crawling profiles, with configurable depth and page limits per host.
- **Optional wordlists:** Discovery of subdomains, directories, and files.
- **Request control:** Configurable jitter, timeouts, response size limits, and error handling.
- **Technology and version detection:** Identification through fingerprints, HTTP headers, and HTML signatures, distinguishing potential indicators from explicitly declared versions.
- **Input surface discovery:** Collection of links, parameters, forms, and input fields, grouping similar structures.
- **Deduplication:** Grouping historical routes by parameters, preserving representative samples, and comparing results against previous scans.
- **Authorization bypass triage:** Negative controls and response comparisons to reduce false positives among potential bypass candidates.
- **Takeover triage:** Collection of DNS/HTTP evidence and identification of URLs requiring further validation.
- **Targeted CVE analysis:** Correlation with a curated catalog, documented preconditions, references, and explicit selection of active vulnerability checkers.
- **Optional OSV integration:** Analysis of packages provided in an inventory, with caching and local verification of results.
- **Execution resumption:** Persistence of task queues and results in JSONL format, allowing recovery after interruptions.
- **Local web dashboard:** Available before data collection begins, featuring filters, priorities, evidence, attack surface relationships, and a per-host URL path tree.
- **Manual review:** Comments, confirmation, dismissal, and tracking of previously reviewed findings.

## Result Organization

Results are categorized from **P1 to P5** according to internal triage criteria. These priorities guide investigation and do not, by themselves, represent definitive severity ratings.

The assessment distinguishes the following states:

- Observed product.
- Potential correlation.
- Preconditions satisfied.
- Reproduced evidence.
- Manually confirmed.
- Dismissed.
- Inconclusive.

The URL path tree organizes URLs by domain and subdomain, consolidating parameters without creating duplicate branches for each GET parameter value. Inferred intermediate levels are identified separately from recorded paths.

## Architecture and Storage

The project consists of a single executable with separate modules for passive and active reconnaissance, extraction, fuzzing, authorization testing, vulnerability analysis, DNS, takeover detection, persistence, and the web interface.

The JSONL journal stores tasks and results. Manual reviews and cached data are maintained in auxiliary files. The dashboard operates on the loopback interface without requiring a database or external web server.

## Requirements and Build Instructions

Requires **Linux and Go 1.24 or later**. Run the following commands from the directory containing `go.mod`:

```bash
go mod download
mkdir -p bin
go build -buildvcs=false -o bin/gohunt .
./bin/gohunt --help
```

Example usage:

```bash
./bin/gohunt --scope escopo.txt \
  --state output/programa.jsonl \
  --jitter-min 300ms \
  --jitter-max 1200ms \
  --crawl-mode balanced
```

By default, the dashboard starts at `http://127.0.0.1:8080`. To resume an interrupted scan, use the same scanning options and add `--resume`.

## Limitations

GoHunt is under active development. CVE coverage and active vulnerability checkers are limited; detecting a potentially vulnerable technology or version requires further investigation.

The tool does not execute JavaScript or automate authenticated sessions. GET form crawling requires explicit activation; POST forms, passwords, and file uploads are not submitted automatically.

Heuristic analysis may produce false positives and false negatives. Potential authorization bypasses and takeover vulnerabilities require impact validation. Historical or inferred paths do not establish current availability.

Execution is sequential, and dashboard queries still traverse the journal. Large state files may result in increased read overhead. Interrupted tasks may cause requests to be repeated when execution resumes.

## Ethical Use and Authorization

GoHunt was developed for research, education, and **explicitly authorized security assessments**.

Use this tool only on assets you own or for which you have obtained valid authorization from the responsible party. When participating in bug bounty programs, comply with the published scope, permitted testing techniques, request rate limits, automation restrictions, and disclosure policies.

The tool's scope configuration is a technical control; authorization must be obtained and verified by the operator. Before execution, be aware that GoHunt enforces scope rules at the hostname level and does not support path- or port-based exclusions.

The operator is responsible for the selected targets, parameters, wordlists, and vulnerability checkers, as well as the handling of collected data and compliance with applicable laws and terms of service.

Avoid service disruptions, unnecessary access to personal data, unauthorized modification of information, and any activities beyond the permissions granted. If sensitive information is exposed, limit data collection to what is strictly necessary to demonstrate the issue and follow responsible disclosure procedures.

All results must be manually reviewed before reporting. The absence of findings does not guarantee security. Do not publish credentials, personal data, sensitive evidence, or third-party assessment results without authorization.

This notice does not grant permission to test third-party systems. The author neither authorizes nor endorses illegal activities or any use outside the permitted scope.
