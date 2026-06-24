# Wazuh ATT&CK Mapper

Resumo
------
Ferramenta para mapear automaticamente alertas e regras Wazuh para técnicas MITRE ATT&CK.

Funcionalidades
--------------
- Parser de alertas Wazuh (JSON).
- Parser de regras Wazuh (XML).
- Motor de mapeamento baseado em regras (fácil de estender).
- Geração de relatórios: JSON, CSV, Markdown e HTML.
- CLI simples.

Instalação
---------
1. Crie e ative um ambiente virtual Python 3.8+:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```
2. Instale dependências:
   ```bash
   pip install -r requirements.txt
   ```

Execução (CLI)
--------------
Exemplos:
- Mapear um arquivo de alertas JSON:
  ```bash
  python -m src.wazuh_mapper.cli examples/alerts.json --outdir out
  ```
- Mapear uma regra Wazuh (XML):
  ```bash
  python -m src.wazuh_mapper.cli examples/rule5710.xml --outdir out
  ```

Arquitetura
---------
- src/wazuh_mapper/parsers.py — parsers de JSON/XML.
- src/wazuh_mapper/mapping.py — motor de mapeamento.
- src/wazuh_mapper/reports.py — geração de relatórios.
- src/wazuh_mapper/cli.py — interface de linha de comando.
- config/attack_mappings.json — mapeamentos configuráveis.
- tests/ — testes automatizados.

Como estender
-------------
- Para adicionar novas técnicas, edite `config/attack_mappings.json` com o novo ID, keywords e regex.
- Para usar um arquivo de mapeamentos customizado:
  ```bash
  python -m src.wazuh_mapper.cli examples/alerts.json --mapping config/attack_mappings.json
  ```

Limitações
---------
- Mapeamento baseado em regras: detecção pode não capturar semântica complexa.
- Integração com LLMs não implementada por padrão (pode ser adicionada como plugin).
- Requer afinação de keywords/regex para reduzir falsos positivos.

Trabalhos futuros
----------------
- Adicionar heurísticas de agregação temporal (correlation across events).
- Integração com modelos ML/LLM locais (opcional) com explicabilidade.
- UI web para visualização interativa dos mapeamentos.

Licença
-------
MIT
