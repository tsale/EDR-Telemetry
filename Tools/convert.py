import pandas as pd
import argparse
from pathlib import Path

parser = argparse.ArgumentParser(
  description='Convert from JSON to CSV and the other way around')
parser.add_argument(
  '-i',
  '--input_file',
  help='The input file to convert depending on the extension',
  required=True)
args = parser.parse_args()
input_file = args.input_file

EXCLUDED_COLUMNS = ["Sub-Category", "Telemetry Feature Category"]

EMOJI_TO_WORDS = {
  "✅": "Yes",
  "❌": "No",
  "⚠️": "Partially",
  "❓": "Pending Response",
  "➖": "N/A",
  "🪵": "Via EventLogs",
  "🎚️": "Via EnablingTelemetry",
  "🎚": "Via EnablingTelemetry",
}

WORDS_TO_EMOJI = {
  "Yes": "✅",
  "No": "❌",
  "Partially": "⚠️",
  "N/A": "➖",
  "Pending Response": "❓",
  "Via EventLogs": "🪵",
  "Via EnablingTelemetry": "🎚️",
}


def replace_values(df, replacements):
  columns = [column for column in df.columns if column not in EXCLUDED_COLUMNS]

  def replace_value(value):
    if not isinstance(value, str):
      return value

    for old_value, new_value in replacements.items():
      value = value.replace(old_value, new_value)
    return value

  df[columns] = df[columns].apply(lambda column: column.map(replace_value))
  return df

def to_json(input_file):
  df = pd.read_csv(input_file)
  df = replace_values(df, EMOJI_TO_WORDS)
  output_file = Path(input_file).with_suffix(".json")
  df.to_json(output_file, orient='records', indent=2, force_ascii=False)
  print(f"\n [*] Successfully converted to {output_file}\n")


def to_csv(input_file):
  df = pd.read_json(input_file)
  df1 = df[['Telemetry Feature Category', 'Sub-Category']]
  df2 = df.drop(['Telemetry Feature Category', 'Sub-Category'], axis=1)
  df2.sort_index(axis=1, level=None, sort_remaining=False, inplace=True)
  df = pd.concat([df1, df2], axis="columns")
  df = replace_values(df, WORDS_TO_EMOJI)

  output_file = Path(input_file).with_suffix(".csv")
  df.to_csv(output_file, index=False)
  print(f"\n [*] Successfully converted to {output_file}\n")


if __name__ == '__main__':
  try:
    if input_file.endswith('.csv'):
      to_json(input_file)
    elif input_file.endswith('.json'):
      to_csv(input_file)
  except Exception as error:
    print("\n\t[*] ", error)
