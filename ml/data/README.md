# Training and evaluation data

Datasets are downloaded by `python -m ml.data.sources` into `ml/.cache/`
(git-ignored). Nothing from them is committed to this repository, and none of
their code is executed: they are read as JSON and text only.

## Sources

| Source | Revision | Licence | Used for |
|---|---|---|---|
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) `runs/` logs | `089ed468cf3ed0322acc66b0211f26d9d90dbf60` | MIT | Real tool results from logged agent runs. A result is an attack if it contains a string from that run's `injections` map; every other tool result is benign |
| [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) `data/` | `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` | MIT | Attacks: `Tool Response` of the base and enhanced test cases. Benign: `attacker_simulated_responses.json` |
| Local text files | pinned by `package-lock.json` | per package | Benign only: up to 40 `.md`, `.json`, `.ts` and `.js` files per package under `node_modules/`, each cut to 20,000 characters, as a filesystem MCP server would return them |

## Row schema

`id`, `text` (normalised), `label` (1 = attack), `source`, `group` (AgentDojo
suite, InjecAgent user tool, or package name), `attack` (attack type, or empty),
`spans` (byte offsets of each injection in the normalised UTF-8 text).

Rows are de-duplicated on the normalised text.

## Counts at the pinned revisions

| Source | Attack | Benign | Groups |
|---|---|---|---|
| AgentDojo | 6,241 | 7,061 | 4 suites |
| InjecAgent | 2,108 | 2,202 | 48 tools |
| Local | 0 | 1,033 | 105 packages |
| **Total** | **8,349** | **10,296** | |

AgentDojo attack types: `important_instructions` and its five variants (3,658),
`ignore_previous` (861), `direct` (851), `injecagent` (351), `tool_knowledge`
(344), and five denial-of-service variants (176).

## How injections are located

AgentDojo tools often return YAML, which re-wraps lines and doubles quotes, so
an injection rarely appears byte-for-byte. Matching compares alphanumeric
characters only and maps the match back to byte offsets. A result containing
at least the first 60 alphanumeric characters of an injection counts as an
attack; a result containing only a 40-character fragment is ambiguous and is
left out.

## Known limitations of the data

- Many AgentDojo attacks differ only in the model or user name they mention,
  so attack rows are less varied than their count suggests.
- AgentDojo and InjecAgent injections are template-generated English text.
- The local benign set is developer documentation and source code; it does not
  cover web pages, email or chat.
