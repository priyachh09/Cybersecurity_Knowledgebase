# Cybersecurity Knowledgebase

This project generates a markdown glossary of cybersecurity terms (threats, tools, frameworks) from YAML files using a Python script.

## Project Structure

Cybersecurity_Knowledgebase/
├── assets/ # sample output screenshots
│   └── 1.png
│   └── 2.png
│   └── 3.png
├── data/
│ ├── threats.yaml # YAML data file with cybersecurity threats
│ ├── tools.yaml # YAML data file with cybersecurity tools
│ ├── frameworks.yaml # YAML data file with cybersecurity frameworks
├── scripts/
│ └── builder.py # Script to generate the glossary Markdown file
├── output/
│ └── glossary.md # Generated Markdown glossary (created by script)
├── README.md # This file

### How to Run
1. Make sure you have Python installed (tested with Python 3.12).
2. Install PyYAML if you haven't already. 
3. Run the builder script from the scripts directory:
            python builder.py
4. The glossary will be generated at output/glossary.md.

#### Example Output Screenshot

Here is how the generated glossary looks in a Markdown viewer: 
(assets/1.png)