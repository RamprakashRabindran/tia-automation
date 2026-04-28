# TIA Report Automation

Python CLI to generate a TechLab-style Threat Intelligence Advisory `.docx` from a single URL.

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
python tia_automation.py --url "https://example.com/threat-article"
```

Optional arguments:

- `--title "Custom Threat Title"` to override auto-derived title.
- `--out-dir "output"` to choose report output folder.

## Output

- File naming: `[TIA] <Title>.docx`
- Default folder: `output/`

Example:

```bash
python tia_automation.py --url "https://www.rapid7.com/blog/post/tr-kyber-ransomware-double-trouble-windows-esxi-attacks-explained/"
```
