import os
import requests
import time
import re
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

def slow_print(text, delay=0.05):
    """Prints the given text with a delay between each character."""
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()  # Ensure there's a newline after the title

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def load_attack_stix_content():
    try:
        response = requests.get("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        console.print(f"Error fetching MITRE ATT&CK content: {e}", style="bold red")
        return None

def load_tools(attack_stix_content):
    tools = {}
    for obj in attack_stix_content.get('objects', []):
        if obj.get('type') == 'tool':
            tools[obj.get('id')] = {"name": obj.get('name'), "description": obj.get('description', 'No description available')}
    return tools

def get_techniques_for_tool(attack_stix_content, tool_id):
    techniques = []
    for obj in attack_stix_content.get('objects', []):
        if obj.get('type') == 'relationship' and obj.get('source_ref') == tool_id and 'attack-pattern' in obj.get('target_ref'):
            tech_id = obj.get('target_ref')
            tech_obj = next((item for item in attack_stix_content.get('objects', []) if item.get('type') == 'attack-pattern' and item.get('id') == tech_id), None)
            if tech_obj:
                kill_chain = ', '.join(phase['phase_name'] for phase in tech_obj.get('kill_chain_phases', []))
                platforms = ', '.join(tech_obj.get('x_mitre_platforms', ['N/A']))
                description = tech_obj.get('description', 'No description available').replace('\n', ' ')
                description += f" (ID: {tech_obj.get('id')})"
                techniques.append({
                    "kill_chain": kill_chain,
                    "name": tech_obj.get('name'),
                    "platform": platforms,
                    "description": description
                })
    return sorted(techniques, key=lambda x: x['kill_chain'])

def get_actors_for_tool(attack_stix_content, tool_id):
    actors = []
    for obj in attack_stix_content.get('objects', []):
        if obj.get('type') == 'relationship' and obj.get('target_ref') == tool_id and 'intrusion-set' in obj.get('source_ref'):
            actor_id = obj.get('source_ref')
            actor_obj = next((item for item in attack_stix_content.get('objects', []) if item.get('type') == 'intrusion-set' and item.get('id') == actor_id), None)
            if actor_obj:
                description = actor_obj.get('description', 'No description available').replace('\n', ' ')
                description += f" (ID: {actor_obj.get('id')})"
                actors.append({
                    "name": actor_obj.get('name'),
                    "description": description
                })
    return actors

def format_description(text):
    """Format text to color parts within [] or () in magenta, add new lines before them, and add indentation."""
    formatted_text = Text("")
    lines = text.split('\n')
    for line in lines:
        parts = re.split(r'(\[.*?\]|\(.*?\))', line)
        formatted_line = Text("    ")  # Add indentation
        skip_newline = False
        for i, part in enumerate(parts):
            if part.startswith("[") and part.endswith("]"):
                if not skip_newline:
                    formatted_line.append("\n    ")  # Add new line and indentation before magenta text
                formatted_line.append(part, style="magenta")
                skip_newline = False  # Reset skip_newline after []
            elif part.startswith("(") and part.endswith(")"):
                formatted_line.append("\n    ")  # Add new line and indentation before magenta text
                formatted_line.append(part, style="magenta")
                skip_newline = True  # Set skip_newline for next part if it's []
            else:
                formatted_line.append(part, style="bold green")
                skip_newline = False  # Reset skip_newline for normal text
        formatted_text.append(formatted_line)
        formatted_text.append("\n")
    return formatted_text

def create_header(title):
    """Create a header with the given title centered and bold."""
    return f"{title}"

def display_related_information(attack_stix_content, selected_tool_id, selected_tool_name, tool_description):
    techniques = get_techniques_for_tool(attack_stix_content, selected_tool_id)
    actors = get_actors_for_tool(attack_stix_content, selected_tool_id)

    description_text = Text("\n")  # Add a new line before the tool description
    description_text.append(format_description(f"{tool_description}\n\n"))

    panel_width = 300  # Adjust the width to match the desired width

    technique_text = Text("\nAssociated Techniques:\n", style="bold yellow")
    if techniques:
        current_kill_chain = None
        for technique in techniques:
            if technique['kill_chain'] != current_kill_chain:
                current_kill_chain = technique['kill_chain']
                header = create_header(current_kill_chain)
                technique_text.append(f"\n{header}\n", style="bold yellow")
            technique_text.append(f"\n* Kill Chain: ", style="green")
            technique_text.append(f"{technique['kill_chain']}\n", style="cyan")
            technique_text.append(f"    Name: ", style="green")
            technique_text.append(f"{technique['name']}\n", style="cyan")
            technique_text.append(f"    Platform: ", style="green")
            technique_text.append(f"{technique['platform']}\n", style="cyan")
            technique_text.append(f"    Description: ", style="green")
            technique_text.append(f"{technique['description']}\n", style="cyan")
    else:
        technique_text.append("No techniques found for this tool.\n", style="bold red")

    actor_text = Text("\nCorrelated Actors:\n", style="bold yellow")
    if actors:
        for actor in actors:
            actor_text.append(f"\n* {actor['name']}:", style="yellow")
            actor_text.append(f" {actor['description']}\n", style="bold cyan")
    else:
        actor_text.append("No correlated actors found for this tool.\n", style="bold red")

    console.print(Panel(description_text + technique_text + actor_text, title=f"{selected_tool_name}", box=box.ROUNDED, width=panel_width))

def display_tools_in_columns(tool_names):
    console.print("\n\n\nSelect a tool to see which actors are known to use it:\n\n", style="bold yellow")
    for index, tool in enumerate(tool_names, 1):
        end_char = '\n\n' if index % 16 == 0 else '  '
        console.print(f"[bold yellow]{index}[/bold yellow]. {tool} ", end=end_char, style="bold cyan")
    console.print()  # Ensure there's a newline at the end

def main():
    attack_stix_content = load_attack_stix_content()
    if not attack_stix_content:
        return

    tools = load_tools(attack_stix_content)
    tool_names = [tool['name'] for tool in tools.values()]
    
    display_tools_in_columns(tool_names)

    try:
        choice = int(console.input("\n\nEnter the number of the Tool: ")) - 1
        if choice < 0 or choice >= len(tool_names):
            raise ValueError("Selection out of range.")
        selected_tool_name = tool_names[choice]
        selected_tool_id = list(tools.keys())[choice]
        tool_description = tools[selected_tool_id]['description']
    except ValueError:
        console.print("Invalid choice. Please enter a valid number.", style="bold red")
        return

    display_related_information(attack_stix_content, selected_tool_id, selected_tool_name, tool_description)
    main()

if __name__ == "__main__":
    clear_screen()
    main()
