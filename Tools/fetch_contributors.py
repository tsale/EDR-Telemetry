import re
import requests

# GitHub repository details
OWNER = "tsale"
REPOSITORY = "EDR-Telemetry"

# Define the README file path
readme_path = "README.md"

# Define the section markers
start_marker = "# ✨ Contributors Wall"
end_marker = "## Current Primary Maintainers"

# Fetch contributors using GitHub API
def fetch_contributors():
    """
    Fetch contributors from GitHub and generate HTML for their icons.
    """
    url = f"https://api.github.com/repos/{OWNER}/{REPOSITORY}/contributors"
    response = requests.get(url)
    
    if response.status_code != 200:
        raise Exception(f"Failed to fetch contributors: {response.status_code}")
    
    contributors = response.json()
    contributors_html = '<div style="display: flex; flex-wrap: wrap; justify-content: center; gap: 10px;">\n'
    
    for contributor in contributors:
        username = contributor["login"]
        avatar_url = contributor["avatar_url"]
        profile_url = contributor["html_url"]
        contributors_html += f"""
  <a href="{profile_url}" target="_blank" style="text-decoration: none;">
    <img src="{avatar_url}" alt="{username}" width="50" height="50" style="border-radius: 50%; display: block; margin: 0;" />
  </a>"""
    
    contributors_html += "\n</div>"
    return contributors_html


# Generate the new content for the Contributors Wall section
def generate_new_content(contributors_html):
    return f"""
# ✨ Contributors Wall

Thanks to these amazing contributors:

<p align="center">
{contributors_html}
</p>
"""

# Update the specific section in the README file
def update_readme(new_section_content):
    # Read the README file
    with open(readme_path, "r") as file:
        readme_content = file.read()
    
    # Use a regex pattern to replace the section
    pattern = re.compile(
        f"{re.escape(start_marker)}.*?{re.escape(end_marker)}", 
        re.DOTALL
    )
    updated_content = pattern.sub(new_section_content + "\n" + end_marker, readme_content)
    
    # Write the updated content back to the README file
    with open(readme_path, "w") as file:
        file.write(updated_content)

    print("README.md has been updated successfully!")

# Main function to orchestrate the process
def main():
    try:
        contributors_html = fetch_contributors()
        new_section_content = generate_new_content(contributors_html)
        update_readme(new_section_content)
    except Exception as e:
        print(f"Error: {e}")

# Execute the script
if __name__ == "__main__":
    main()
