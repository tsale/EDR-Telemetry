import pandas as pd
import argparse
import json

parser = argparse.ArgumentParser(
  description='Convert from JSON to CSV and the other way around')
parser.add_argument(
  '-i',
  '--input_file',
  help='The input file to convert depending on the extension',
  required=True)
args = parser.parse_args()
input_file = args.input_file

def replace_to_words(file):
    # Replace the target words with the replacement words
    words_to_replace = {
    "\u2705": "Yes",        # ✅ Implemented
    "\u274C": "No",    # ❌ Not Implemented
    "\u26A0\uFE0F": "Partially", # ⚠️ Partially Implemented
    "\u2753": "Pending Response",   # ❓ Pending Response
    "\uD83E\uDEB5" : "Via EventLogs", # 🪵 Via EventLogs
    "\ud83c\udf9a️" : "Via EnablingTelemetry"  # 🎚️ Via EnablingTelemetry
}
    # Read the JSON file
    with open(file, "r", encoding='utf-8') as f:
      data = json.load(f)
    
    # Replace values but skip "Sub-Category" and "Telemetry Feature Category" keys
    for item in data:
      for key, value in item.items():
        if key not in ["Sub-Category", "Telemetry Feature Category"]:
          if isinstance(value, str):
            for emoji, word in words_to_replace.items():
              value = value.replace(emoji, word)
            item[key] = value
    
    try:
      with open(file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    except PermissionError:
      print(PermissionError)
      pass

def replace_from_words(file):
    # Replace the target words with the replacement words
    words_to_replace = {
        "Yes": "✅",
        "No" : "❌",
        "Partially" : "⚠️",
        "N/A" : "➖",
        "Pending Response" : "❓",
        "Via EventLogs" : "🪵",
        "Via EnablingTelemetry" : "🎚️"
         #Add more words as needed
    }
    # Read the CSV file
    with open(file, "r") as f:
      lines = f.readlines()
    
    # Skip replacement in the header (first line) and first two columns
    for i in range(1, len(lines)):
      # Split the line by comma
      parts = lines[i].split(',')
      # Replace only in columns after the first two
      for j in range(2, len(parts)):
        for key, value in words_to_replace.items():
          parts[j] = parts[j].replace(key, value)
      # Join back together
      lines[i] = ','.join(parts)
    
    try:
      with open(file, 'w', encoding='utf-8') as f:
        f.writelines(lines)
    except PermissionError:
      print(PermissionError)
      pass

def to_json(input_file):
  df = pd.read_csv(input_file)
  input_file = input_file.split(".")[0] + ".json"
  df.to_json(input_file, orient='records', indent=2)
  replace_to_words(input_file)
  print(f"\n [*] Successfully converted to {input_file}\n")


def to_csv(input_file):
  df = pd.read_json(input_file)
  df1 = df[['Telemetry Feature Category', 'Sub-Category']]
  df2 = df.drop(['Telemetry Feature Category', 'Sub-Category'], axis=1)
  df2.sort_index(axis=1, level=None, sort_remaining=False, inplace=True)
  df = pd.concat([df1, df2], axis="columns")

  input_file = input_file.split(".")[0] + ".csv"
  df.to_csv(input_file, index=False)
  replace_from_words(input_file)
  print(f"\n [*] Successfully converted to {input_file}\n")


if __name__ == '__main__':
  try:
    if input_file.endswith('.csv'):
      to_json(input_file)
    elif input_file.endswith('.json'):
      to_csv(input_file)
  except Exception as error:
    print("\n\t[*] ", error)
