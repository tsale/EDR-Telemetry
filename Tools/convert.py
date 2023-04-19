import pandas as pd
import argparse

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
        "\uD83D\uDFE9" : "Yes",
        "\uD83D\uDFE5" : "No",
        "\uD83D\uDFE7" : "Partially",
        "\u2796" : "N/A",
        "\u2753" : "Pending Response",
        "\uD83E\uDEB5" : "Via EventLogs"
        # Add more words as needed
    }
    # Read the JSON file
    with open(file, "rb") as f:
      data = f.read()
      data = data.decode("unicode_escape")
      for key,value in words_to_replace.items():
        if key in data:
          data = data.replace(key,value)
          try:
            with open(file, 'w+',errors="ignore") as f:
                # Writing the replaced data in our
                # text file
                f.write(data)
          except PermissionError:
            print(PermissionError)
            pass
        else:
          pass

def replace_from_words(file):
    # Replace the target words with the replacement words
    words_to_replace = {
        "Yes": "🟩",
        "No" : "🟥",
        "Partially" : "🟧",
        "N/A" : "➖",
        "Pending Response" : "❓",
        "Via EventLogs" : "🪵"
         #Add more words as needed
    }
    # Read the CSV file
    with open(file, "r") as f:
      data = f.read()
      for key,value in words_to_replace.items():
        if key in data:
          data = data.replace(key,value)
          try:
            with open(file, 'w',encoding='utf-8') as f:
                # Writing the replaced data in our
                # text file
                f.write(data)
          except PermissionError:
            print(PermissionError)
            pass
        else:
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
