# SPAF Command Reference

This is a quick reference for all available SPAF commands.

## Core Commands
| Command | Arguments | Description |
| :--- | :--- | :--- |
| `recon` | `<target>` | Active/Passive domain reconnaissance |
| `network` | `<target>` | Async Nmap service discovery with CVE mapping |
| `webscan` | `<url>` | Web application security analysis |
| `crawl` | `<url>` | Deep spidering for sensitive files |

## AI Commands
| Command | Arguments | Description |
| :--- | :--- | :--- |
| `analyze` | `--id` / `--file` | Advanced AI offensive security analysis |
| `poc` | `<finding_id>` | Generate functional exploit Python script |
| `chat` | `<query>` | General security assistance chat |
| `gemini` | `<query>` | Dedicated Google Gemini shortcut |
| `remediate`| `<finding_id>` | Generate Ansible/Terraform fix code |

## Operational Commands
| Command | Arguments | Description |
| :--- | :--- | :--- |
| `watch` | `<target>` | Shadow Scan: 24/7 monitoring and alerts |
| `shell` | | Interactive SPAF security terminal |
| `report` | `<target>` | Generate premium HTML/JSON reports |
| `history` | | View past scan records |
| `login` | | Authenticate with Antigravity Cloud |
| `setup` | | Interactive configuration wizard |
| `test-ai` | | Verify AI provider connectivity |

## Global Options
*   `--no-db`: Run in offline/no-database mode.
*   `--help`: Show detailed help for any command.

## Stealth (Configured via .env)
*   `USE_TOR`: Enable/Disable TOR routing.
*   `PROXY_FILE`: Path to rotating proxy list.
*   `RANDOM_USER_AGENT`: Enable browser fingerprint rotation.
