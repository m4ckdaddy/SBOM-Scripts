import json
import csv
import argparse

def extract_components(json_file):
    with open(json_file, 'r') as file:
        data = json.load(file)
    components = data.get('components', [])
    return components

def write_to_csv(components, output_file):
    csv_columns = ['Type', 'Name', 'Hashes', 'Properties']
    csv_data = []

    for component in components:
        hashes = "; ".join([f"{h['alg']}: {h['content']}" for h in component.get('hashes', [])])
        properties = "; ".join([f"{p['name']}: {p['value']}" for p in component.get('properties', [])])
        csv_data.append({
            'Type': component.get('type', ''),
            'Name': component.get('name', ''),
            'Hashes': hashes,
            'Properties': properties
        })

    with open(output_file, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=csv_columns)
        writer.writeheader()
        writer.writerows(csv_data)

def main():
    parser = argparse.ArgumentParser(description="Extract third-party libraries from SBOM JSON file to CSV.")
    parser.add_argument("json_file", help="Path to the SBOM JSON file")
    parser.add_argument("-o", "--output", help="Output CSV file path", default="third_party_libraries.csv")
    args = parser.parse_args()

    components = extract_components(args.json_file)
    write_to_csv(components, args.output)
    print(f"Data extracted to {args.output}")

if __name__ == "__main__":
    main()
