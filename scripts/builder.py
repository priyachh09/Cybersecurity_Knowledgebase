import yaml
import os

categories = ["threats","tools","frameworks"]

output_file = "../output/glossary.md"


def read_yaml(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)
    
def write_section(out, category, data, cat_index):
    out.write(f"## {cat_index} {category.capitalize()}\n\n")

    for i, item in enumerate(data,start=1):
        out.write(f"### {cat_index}.{i} {item['term']}\n")
        out.write(f"**Description:** \n {item['description']}\n\n")

        if category == "threats":
            if 'examples' in item:
                out.write("**Examples:**\n")
                for ex in item['examples']:
                    out.write(f"- {ex}\n")
                out.write("\n")

            if 'mitigation' in item:
                out.write("**Mitigation:**\n")
                for mit in item['mitigation']:
                    out.write(f"- {mit}\n")
                out.write("\n")

        elif category == "tools":
            if 'use_cases' in item:
                out.write("**Use Cases:**\n")
                for uc in item['use_cases']:
                    out.write(f"- {uc}\n")
                out.write("\n")

            if 'platform' in item:
                out.write(f"**Platform:** {item['platform']}\n")
            out.write("\n")

        elif category == "frameworks":
            if 'source' in item:
                out.write(f"**Source:** \n {item['source']}\n")
            out.write("\n")

            if 'compliance_areas'in item:
                out.write("**Compliance Areas:**\n")
                for ca in item['compliance_areas']:
                    out.write(f"- {ca} \n")
                out.write("\n")

    out.write("\n-----------------------------------------------------------------------------------------------------------------------------------------------------\n")

def main():
    os.makedirs("../output", exist_ok=True)

    with open(output_file, 'w', encoding='utf-8') as out:
        out.write("# Cybersecurity Knowledgebase\n\n")
        for idx, category in enumerate(categories, start=1):
            yaml_path = f"../data/{category}.yaml"
            data =read_yaml(yaml_path)
            write_section(out, category, data, idx)
    print(f" Glossary generated at {output_file}")


if __name__ == "__main__":
    main()