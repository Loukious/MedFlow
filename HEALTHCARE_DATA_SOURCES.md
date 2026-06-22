# Healthcare Data Sources Used By MedFlow

This file distinguishes between datasets that were actually downloaded and ingested locally, and useful reference sources that were identified but not downloaded.

## Downloaded Locally

The following datasets were successfully downloaded with `scripts/download_kaggle_healthcare.py --all` and copied into:

```text
data/kaggle
```

| Source | Type | Local Path | Source URL |
|---|---|---|---|
| Health Care Cyber Security Dataset | Kaggle dataset | `data/kaggle/health-care-cyber-security/healthcare_cybersecurity_dataset.csv` | https://www.kaggle.com/datasets/hussainsheikh03/health-care-cyber-security |
| Healthcare Ransomware Dataset | Kaggle dataset | `data/kaggle/healthcare-ransomware/Healthcare Ransomware Dataset.csv` | https://www.kaggle.com/datasets/rivalytics/healthcare-ransomware-dataset |
| Healthcare Ransomware Dataset Documentation | Kaggle PDF documentation | `data/kaggle/healthcare-ransomware/Healthcare Ransomware Dataset Documentation.pdf` | https://www.kaggle.com/datasets/rivalytics/healthcare-ransomware-dataset |
| MedSec-25: IoMT Cybersecurity Dataset | Kaggle dataset | `data/kaggle/medsec-25-iomt/MedSec-25.csv` | https://www.kaggle.com/datasets/abdullah001234/medsec-25-iomt-cybersecurity-dataset |
| IoT Healthcare Security Dataset - Attack | Kaggle dataset | `data/kaggle/iot-healthcare-security/ICUDatasetProcessed/Attack.csv` | https://www.kaggle.com/datasets/faisalmalik/iot-healthcare-security-dataset |
| IoT Healthcare Security Dataset - Environment Monitoring | Kaggle dataset | `data/kaggle/iot-healthcare-security/ICUDatasetProcessed/environmentMonitoring.csv` | https://www.kaggle.com/datasets/faisalmalik/iot-healthcare-security-dataset |
| IoT Healthcare Security Dataset - Patient Monitoring | Kaggle dataset | `data/kaggle/iot-healthcare-security/ICUDatasetProcessed/patientMonitoring.csv` | https://www.kaggle.com/datasets/faisalmalik/iot-healthcare-security-dataset |
| Healthcare Cybersecurity Vulnerabilities Dataset | Kaggle dataset | `data/kaggle/healthcare-vulnerabilities/healthcare_cybersecurity_10k.csv` | https://www.kaggle.com/datasets/chuneeb/healthcare-cybersecurity-vulnerabilities-dataset |

## Local CSV Row Counts

These are the raw CSV row counts found locally.

| Local CSV | Raw Rows | Columns |
|---|---:|---:|
| `data/kaggle/health-care-cyber-security/healthcare_cybersecurity_dataset.csv` | 1,423 | 19 |
| `data/kaggle/healthcare-ransomware/Healthcare Ransomware Dataset.csv` | 5,000 | 16 |
| `data/kaggle/healthcare-vulnerabilities/healthcare_cybersecurity_10k.csv` | 2,133 | 11 |
| `data/kaggle/iot-healthcare-security/ICUDatasetProcessed/Attack.csv` | 80,126 | 52 |
| `data/kaggle/iot-healthcare-security/ICUDatasetProcessed/environmentMonitoring.csv` | 31,758 | 52 |
| `data/kaggle/iot-healthcare-security/ICUDatasetProcessed/patientMonitoring.csv` | 76,810 | 52 |
| `data/kaggle/medsec-25-iomt/MedSec-25.csv` | 554,534 | 84 |

## Ingested Into Chroma

The ingestion code caps each CSV at 5,000 rows to keep the vector database practical for local use.

```text
health-care-cyber-security: 1,423 rows
healthcare-ransomware: 5,000 rows
healthcare-vulnerabilities: 1,515 rows
iot-healthcare-security: 15,000 rows
medsec-25-iomt: 5,000 rows
total healthcare rows ingested: 27,938
detection_db total documents after ingestion: 30,543
```

The ingested healthcare rows are stored in the Chroma `detection_db` collection with metadata:

```text
type=healthcare-dataset-row
dataset=<dataset folder name>
name=<csv file name>
path=<local csv path>
```

## Downloader Commands

List known Kaggle datasets:

```bash
python scripts/download_kaggle_healthcare.py --list
```

Download all supported Kaggle datasets:

```bash
python scripts/download_kaggle_healthcare.py --all
```

Download one dataset by short name:

```bash
python scripts/download_kaggle_healthcare.py --dataset healthcare-vulnerabilities
python scripts/download_kaggle_healthcare.py --dataset iot-healthcare-security
```

Ingest downloaded CSV files:

```bash
python -m medflow_ti.cli ingest-healthcare-csv data/kaggle
```

## Reference Sources Not Downloaded

These sources were identified as useful for future enrichment, but they were not downloaded or ingested during this build. Some require forms, email submission, manual portal interaction, separate cloning, or custom parsers.

| Source | Type | Reason Not Downloaded | URL |
|---|---|---|---|
| CICIoMT2024 | IoMT attack dataset | Requires manual form/email access on the provider site. | https://www.unb.ca/cic/datasets/iomt-dataset-2024.html |
| WUSTL-EHMS-2020 | IoMT/e-health monitoring dataset | Not downloaded; separate manual/source-specific acquisition needed. | https://www.cse.wustl.edu/~jain/ehms/index.html |
| IoT Healthcare Security Dataset GitHub mirror/code | GitHub mirror/code | Not cloned; Kaggle version was downloaded instead. | https://github.com/imfaisalmalik/IoT-Healthcare-Security-Dataset |
| HHS OCR Breach Portal | Healthcare breach reports | Web portal, not downloaded; would need a dedicated scraper/export workflow. | https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf |
| HHS OCR Breaches Under Investigation | Healthcare breach investigation page | Web portal, not downloaded; would need a dedicated scraper/export workflow. | https://ocrportal.hhs.gov/ocr/breach/breach_report_hip.jsf |
| VERIS Community Database / VCDB official page | Incident corpus page | Not downloaded; reference page only. | https://verisframework.org/vcdb.html |
| VCDB GitHub repository | Incident corpus repository | Not cloned or ingested. | https://github.com/vz-risk/VCDB |
| HC3 / HHS healthcare cybersecurity bulletins and analyst notes | Healthcare-sector cyber bulletins | Not downloaded; would need page/PDF collection and parsing. | https://asprtracie.hhs.gov/technical-resources/86/cybersecurity/0 |
| CISA Known Exploited Vulnerabilities Catalog | Official KEV catalog | Not downloaded; can be added later from CISA CSV/JSON. | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| CISA KEV data GitHub mirror | CSV/JSON repository | Not cloned or ingested. | https://github.com/cisagov/kev-data |
| ThreatIntel-Reports GitHub repository | Extracted CTI reports repository | Not cloned or ingested. | https://github.com/mthcht/ThreatIntel-Reports |
| ThreatIntel-Reports web interface | Searchable CTI report interface | Web interface only; not downloaded. | https://mthcht.github.io/ThreatIntel-Reports/ |
| TRAM - MITRE/CTID | ATT&CK report mapper | Tool repository, not dataset ingestion source; not cloned. | https://github.com/center-for-threat-informed-defense/tram |
| TRAM - MITRE ATT&CK GitHub repository | ATT&CK report mapper | Tool repository, not dataset ingestion source; not cloned. | https://github.com/mitre-attack/tram |
| FDA MAUDE Database | Medical device adverse event reports | Web search portal, not downloaded; needs custom export/parser workflow. | https://www.accessdata.fda.gov/scripts/cdrh/cfdocs/cfmaude/search.cfm |
| FDA MDR / MAUDE downloadable data files | Downloadable medical device reporting files | Not downloaded; would need a separate data-file parser. | https://www.fda.gov/medical-devices/medical-device-reporting-mdr-how-report-medical-device-problems/mdr-data-files |

