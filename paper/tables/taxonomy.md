| Class | Name | STRIDE | OWASP LLM | OWASP ASI | ATLAS | Controls | Incidents |
|---|---|---|---|---|---|---|---|
| T01 | Indirect prompt injection via workspace and retrieved content | TE | LLM01 | ASI01 | AML.T0051.001, AML.T0093, AML.T0068, AML.T0094 | D01, D02, D03, D04, D11 | 14 |
| T02 | Repository and workspace configuration as code execution | ET | LLM06 | ASI05, ASI02 | AML.T0081, AML.T0050, AML.T0053 | D04, D01, D02, D05, D14 | 52 |
| T03 | Permission-model weaknesses and approval bypass | ET | LLM06 | ASI02, ASI03 | AML.T0053, AML.T0050, AML.T0102 | D01, D02, D14 | 74 |
| T04 | MCP trust: tool poisoning, rug pulls, OAuth and server identity | STE | LLM03, LLM01, LLM06 | ASI04, ASI02 | AML.T0110, AML.T0109, AML.T0011.002, AML.T0010.005, AML.T0099, AML.T0131 | D05, D14, D06, D13, D03 | 15 |
| T05 | Skills, plugins, extensions and marketplaces | STE | LLM03 | ASI04 | AML.T0010.005, AML.T0115.002, AML.T0011.001, AML.T0111 | D06, D13, D14 | 2 |
| T06 | Harness distribution and dependency supply chain | TSE | LLM03 | ASI04 | AML.T0010.001, AML.T0011.001, AML.T0010, AML.T0083 | D13, D15, D14 | 9 |
| T07 | Secret exposure and residue | I | LLM02 | ASI03 | AML.T0055, AML.T0083, AML.T0037, AML.T0098 | D07, D11, D12 | 12 |
| T08 | Data exfiltration channels | I | LLM02, LLM05 | ASI02 | AML.T0086, AML.T0077, AML.T0025, AML.T0057 | D03, D02, D01 | 23 |
| T09 | Headless and CI abuse (pwn request) | EIT | LLM01, LLM06 | ASI01, ASI02, ASI03 | AML.T0051.001, AML.T0093, AML.T0119, AML.T0053 | D08, D01, D14, D07 | 5 |
| T10 | Persistent memory and long-lived context poisoning | TE | LLM04 | ASI06 | AML.T0080.000, AML.T0080, AML.T0081 | D09, D11 | 2 |
| T11 | Sub-agent and cross-harness trust propagation | ES | LLM06 | ASI03, ASI07, ASI08 | AML.T0118, AML.T0118.001, AML.T0053 | D10, D01, D02 | 2 |
| T12 | Browser and computer-use surfaces | SIE | LLM01, LLM06 | ASI01, ASI02 | AML.T0100, AML.T0078, AML.T0113, AML.T0112.000 | D02, D03, D01 | 1 |
| T13 | Multi-tenant isolation and authorization | IES | LLM02 | ASI03 | AML.T0085, AML.T0091 | D14, D10, D07 | 7 |
| T14 | Destructive and unsafe autonomous actions | DT | LLM06 | ASI02, ASI08 | AML.T0101, AML.T0048.000 | D01, D02, D14 | 0 |
| T15 | Telemetry, data residency, retention and audit gaps | IR | LLM02 |  |  | D12, D11, D14 | 1 |
| T16 | Offensive misuse of harnesses by attackers | E |  | ASI10 | AML.T0124, AML.T0116, AML.T0117 | D11, D14 | 3 |
| T17 | Execution sandbox and isolation escape | E | LLM06 | ASI05 | AML.T0105, AML.T0097 | D02, D10, D03 | 22 |
| T18 | Agent control-plane exposure and authorization | SEI |  | ASI03 | AML.T0132, AML.T0006.002, AML.T0049, AML.T0122, AML.T0078 | D16, D01, D04 | 34 |
| T19 | Conventional software defects in agent runtimes and SDKs | TDE | LLM05, LLM10 | ASI05 | AML.T0049, AML.T0029 | D15, D13, D02 | 45 |
