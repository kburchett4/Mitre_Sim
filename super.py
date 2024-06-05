import os
import requests
import re
import math
import time
import click
import inquirer
from rich.console import Console

from rich.table import Table
from rich import box
from rich.text import Text
from rich.panel import Panel

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

def get_all_threat_actors(attack_stix_content):
    threat_actors = []
    for obj in attack_stix_content.get('objects', []):
        if obj.get('type') == 'intrusion-set':
            description = obj.get('description', '')
            geo_info = extract_geo_info(description)
            activity_type = extract_activity_type(description)
            target_sector = extract_target_sector(description)
            threat_actors.append({
                "name": obj.get('name'),
                "geo_info": geo_info,
                "activity_type": activity_type,
                "target_sector": target_sector
            })
    return sorted(threat_actors, key=lambda x: x['name'])

def extract_geo_info(description):
    geo_keywords = ["China", "Russia", "Iran", "North Korea", "USA", "Vietnam", "India", "Europe"]
    for keyword in geo_keywords:
        if keyword.lower() in description.lower():
            return keyword
    return "Unknown"

def extract_activity_type(description):
    activity_keywords = ["espionage", "financial", "theft", "sabotage", "ransomware", "malware"]
    for keyword in activity_keywords:
        if keyword.lower() in description.lower():
            return keyword.capitalize()
    return "Other"

def extract_target_sector(description):
    sector_keywords = ["government", "financial", "healthcare", "technology", "energy", "military"]
    for keyword in sector_keywords:
        if keyword.lower() in description.lower():
            return keyword.capitalize()
    return "Other"

def get_actor_id(attack_stix_content, actor_name):
    for obj in attack_stix_content.get('objects', []):
        if obj.get('type') == 'intrusion-set' and obj.get('name').lower() == actor_name.lower():
            return obj.get('id')
    return None

def get_techniques_for_actor(attack_stix_content, actor_id):
    techniques = []
    for obj in attack_stix_content.get('objects', []):
        if obj.get('type') == 'relationship' and obj.get('source_ref') == actor_id and 'attack-pattern' in obj.get('target_ref'):
            tech_id = obj.get('target_ref')
            tech_obj = next((item for item in attack_stix_content.get('objects', []) if item.get('type') == 'attack-pattern' and item.get('id') == tech_id), None)
            if tech_obj:
                tech_obj['platforms'] = ', '.join(tech_obj.get('x_mitre_platforms', ['N/A']))
                tech_obj['kill_chain_phase'] = ', '.join(phase['phase_name'] for phase in tech_obj.get('kill_chain_phases', []))
                techniques.append(tech_obj)
    return techniques

def display_techniques(techniques, actor_name, total_techniques, start_index):
    clear_screen()
    
    table = Table(title=f"Techniques for {actor_name} - Total Techniques: {total_techniques}", 
                  box=box.SIMPLE_HEAD, show_lines=True, header_style="bold magenta", show_edge=True)
    
    table.add_column("No.", style="dim", width=6)
    table.add_column("Name", justify="left", width=20, style="bold bright_green")
    table.add_column("Platform", justify="left", width=20, style="bright_cyan")
    table.add_column("Kill Chain Phase", justify="left", width=20, style="bright_yellow")
    table.add_column("Description", overflow="fold", width=170)

    for i, technique in enumerate(techniques, start=start_index):
        description_lines = technique.get('description', 'N/A').split('\n')
        formatted_description_lines = []
        for line in description_lines:
            if line.strip().startswith("*"):
                formatted_description_lines.append(f"[green]•[/green]{line[1:].strip()}")
            else:
                formatted_description_lines.append(f"    {line}")
        formatted_description = "\n".join(formatted_description_lines)

        table.add_row(
            str(i),
            technique['name'],
            technique.get('platforms', 'N/A'),
            technique.get('kill_chain_phase', 'N/A'),
            formatted_description
        )

    console.print(table)

def display_threat_actors_by_geo(threat_actors):
    geo_groups = {}
    for actor in threat_actors:
        geo_info = actor['geo_info']
        if geo_info not in geo_groups:
            geo_groups[geo_info] = []
        geo_groups[geo_info].append(actor)

    table = Table(show_header=True, header_style="bold green", box=box.SIMPLE_HEAD, show_lines=True, show_edge=True)
    for geo_info in geo_groups.keys():
        table.add_column(geo_info, style="bold cyan")

    actor_list = []
    index = 1

    max_actors = max(len(actors) for actors in geo_groups.values())
    num_columns = min(6, console.size.width // 15)
    num_rows = math.ceil(max_actors / num_columns)

    for row in range(num_rows):
        row_data = []
        for geo_info, actors in geo_groups.items():
            if row < len(actors):
                actor_list.append(actors[row]['name'])
                row_data.append(f"{index}. {actors[row]['name']}")
                index += 1
            else:
                row_data.append("")
        table.add_row(*row_data)

    console.print(table)
    return actor_list

def display_threat_actors_by_activity(threat_actors):
    activity_groups = {}
    for actor in threat_actors:
        activity_type = actor['activity_type']
        if activity_type not in activity_groups:
            activity_groups[activity_type] = []
        activity_groups[activity_type].append(actor)

    table = Table(show_header=True, header_style="bold green", box=box.SIMPLE_HEAD, show_lines=True, show_edge=True)
    for activity_type in activity_groups.keys():
        table.add_column(activity_type, style="bold cyan")

    actor_list = []
    index = 1

    max_actors = max(len(actors) for actors in activity_groups.values())
    num_columns = min(6, console.size.width // 15)
    num_rows = math.ceil(max_actors / num_columns)

    for row in range(num_rows):
        row_data = []
        for activity_type, actors in activity_groups.items():
            if row < len(actors):
                actor_list.append(actors[row]['name'])
                row_data.append(f"{index}. {actors[row]['name']}")
                index += 1
            else:
                row_data.append("")
        table.add_row(*row_data)

    console.print(table)
    return actor_list

def display_threat_actors_by_sector(threat_actors):
    sector_groups = {}
    for actor in threat_actors:
        target_sector = actor['target_sector']
        if target_sector not in sector_groups:
            sector_groups[target_sector] = []
        sector_groups[target_sector].append(actor)

    table = Table(show_header=True, header_style="bold green", box=box.SIMPLE_HEAD, show_lines=True, show_edge=True)
    for target_sector in sector_groups.keys():
        table.add_column(target_sector, style="bold cyan")

    actor_list = []
    index = 1

    max_actors = max(len(actors) for actors in sector_groups.values())
    num_columns = min(6, console.size.width // 15)
    num_rows = math.ceil(max_actors / num_columns)

    for row in range(num_rows):
        row_data = []
        for target_sector, actors in sector_groups.items():
            if row < len(actors):
                actor_list.append(actors[row]['name'])
                row_data.append(f"{index}. {actors[row]['name']}")
                index += 1
            else:
                row_data.append("")
        table.add_row(*row_data)

    console.print(table)
    return actor_list

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
    """Format text to color parts within [] or () in magenta and add indentation."""
    formatted_text = Text("")
    lines = text.split('\n')
    for line in lines:
        parts = re.split(r'(\[.*?\]|\(.*?\))', line)
        formatted_line = Text("    ")  # Add indentation
        for part in parts:
            if part.startswith("[") and part.endswith("]"):
                formatted_line.append(part, style="magenta")
            elif part.startswith("(") and part.endswith(")"):
                formatted_line.append(part, style="magenta")
            else:
                formatted_line.append(part, style="bold green")
        formatted_text.append(formatted_line)
        formatted_text.append("\n")  # Add a single newline after each formatted line
    return formatted_text

def create_header(title):
    """Create a header with the given title centered and bold."""
    return f"{title}"

def display_related_information(attack_stix_content, selected_tool_id, selected_tool_name, tool_description):
    techniques = get_techniques_for_tool(attack_stix_content, selected_tool_id)
    actors = get_actors_for_tool(attack_stix_content, selected_tool_id)

    description_text = Text("\n")  # Add a new line before the tool description
    description_text.append(format_description(f"{tool_description}\n\n"))

    panel_width = 360  # Adjust the width to match the desired width

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

def display_threat_scope_menu():
    menu_options = [
        'Threat Actors',
        'Tools',
        'Exit'
    ]
    questions = [
        inquirer.List('menu',
                      message="Select an option".upper(),
                      choices=menu_options)
    ]
    menu_choice = inquirer.prompt(questions)['menu']
    return menu_choice

def display_title_screen():
    clear_screen()
    title_art = """
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    
                                                x$                                                  
                                              x$xxxxx;;:::::;;+;++xXX                               
                                             x$xxxxx++:::::;+++++XXXXx                      +xxx    
                                             xXXxXxxx;:::;:;:;;xxXXxxx                    xxxx$$    
                                              $$$$$Xx::::::;+xxxXXxxxX                xxxxxXx;+     
                                              $$$$$$$x:;;::::xxxxx             ;;++;;;;;;;;;+xxxx   
                                                       +:::::::::+;::......::;++++++++++++++x&$$x   
       ....:.::::::...........:;+;x+x;++++++;++;:..:;;;;:::...........;+++;:::::::++++++++++x+xxxx  
    :::::::;:::::::::::::::::::xxxxxxxxxxxxxx+:::::;;;::::::::::::::::::x:::....:+++++++++++xXXXXXx 
  :::::::::::::::::::::::::::::::;;;;;;;;;;:::::.:.::::.::.:.:.:.:.::.:.:..::::+++++++++++xXXXxxxXX 
 ::::::::::;;;;;;;:;++:x+:::::::::::::::::::::::::::::::::::::::::::::;xxx++++++++++++++++x$xxxxxxx 
  +;:::::::;::;;;;;;;;:+;:::::::::::::::::::xxxxxxxxxxxxxx++xxxxxx++++++++++++++++++++++++X$$xxxxxx 
       ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx$$Xxxxxx  
          +++;;;;+++++++++++++++++++++++;++xXxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx   
               ::::::::::::::::::::::::::::xxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXxxx+++++++++xXXXXxxxx     
               ;;::::::::::::;xxxxxxX :+xxxxXXX                            x++++++++++xxxx          
                ;;;;:::::::::+xxxxxx                                      xx++xxx++xxxXXx           
                 ;;;;;;::::::::;;;;+                                      xxx++++++xxx              
                  ;;;;;;;;;:::.:;;;;+                                     xxx++xxxxXX               
      xxxxxxxxxxx++xxx;;;;;;;;;++xxxx                                     xx+++xxxX$x               
     xxxxxxxxxxxxxxxxxxxxx;;;;xxxxxx                                      xx++xxxxX$                
    xxxxXXxXXxxxxxxxxxxxxxxxxxxxxx                                        xxx+xxxxXX                
                Xxxxxxxxxxxxx$$XX                                        +xxxxxxxX$x                
                   xxxxxxxxxx+xxxxx                                      xxx+xxxxxX                 
                     xxxxxxxxX$$$$                                       xxx+xxxxXX                 
                       xxxxxX$$$$                                       +xxxxxxxx$x                 
                        xxxx$$$$X                                       xxx++xxxXX                  
                         xx$$$$$                                        xxx+++++++                  
                                                                       +xxx+++++xx                  
                                                                       xxx+++++xxx                  
                                                                        xxxxxxXXX                   
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    
    """
    console.print(title_art, style="bold green")
    console.print("Threat Scope\n", style="bold yellow bold underline")

@click.command()
def main():
    attack_stix_content = load_attack_stix_content()
    if not attack_stix_content:
        console.print("Failed to load attack STIX content.", style="bold red")
        return

    while True:
        display_title_screen()
        menu_choice = display_threat_scope_menu()

        if menu_choice == 'Exit':
            break

        if menu_choice == 'Threat Actors':
            threat_actors = get_all_threat_actors(attack_stix_content)

            actor_menu_options = [
                'Geographical Region', 
                'Activity Type', 
                'Target Sector', 
                'Back to Main Menu'
            ]
            questions = [
                inquirer.List('actor_menu',
                              message="Select an option".upper(),
                              choices=actor_menu_options)
            ]
            actor_menu_choice = inquirer.prompt(questions)['actor_menu']

            if actor_menu_choice == 'Back to Main Menu':
                continue

            if actor_menu_choice == 'Geographical Region':
                actor_list = display_threat_actors_by_geo(threat_actors)
            elif actor_menu_choice == 'Activity Type':
                actor_list = display_threat_actors_by_activity(threat_actors)
            elif actor_menu_choice == 'Target Sector':
                actor_list = display_threat_actors_by_sector(threat_actors)

            try:
                choice = int(console.input("[bold yellow]Enter the number of the Threat Actor: [/]")) - 1
                if choice < 0 or choice >= len(actor_list):
                    raise ValueError("Invalid choice number.")
                selected_actor = actor_list[choice]
            except ValueError as e:
                console.print("Invalid choice. Please enter a valid number.", style="bold red")
                continue

            actor_id = get_actor_id(attack_stix_content, selected_actor)
            if not actor_id:
                console.print(f"Could not find the selected actor: {selected_actor}.", style="bold red")
                continue

            techniques = get_techniques_for_actor(attack_stix_content, actor_id)
            if not techniques:
                console.print(f"No techniques found for the selected actor: {selected_actor}.", style="bold red")
                continue

            page_size = 5
            total_pages = math.ceil(len(techniques) / page_size)

            current_page = 1
            while True:
                start_index = (current_page - 1) * page_size
                end_index = start_index + page_size
                page_techniques = techniques[start_index:end_index]
                
                display_techniques(page_techniques, selected_actor, len(techniques), start_index + 1)
                
                if current_page == total_pages:
                    nav = console.input(f"[bold yellow]Page {current_page}/{total_pages}. Press Enter to start over, 'p' for previous, 'q' to quit: [/]").lower()
                    if nav == '' or nav == 'q':
                        break
                    elif nav == 'p' and current_page > 1:
                        current_page -= 1
                    else:
                        console.print("Invalid input.", style="bold red")
                else:
                    nav = console.input(f"[bold yellow]Page {current_page}/{total_pages}. Press Enter for next, 'p' for previous, 'q' to quit: [/]").lower()
                    if nav == '' and current_page < total_pages:
                        current_page += 1
                    elif nav == 'p' and current_page > 1:
                        current_page -= 1
                    elif nav == 'q':
                        break
                    else:
                        console.print("Invalid input.", style="bold red")

        elif menu_choice == 'Tools':
            tools = load_tools(attack_stix_content)
            tool_names = [tool['name'] for tool in tools.values()]
            
            while True:
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
                    continue

                display_related_information(attack_stix_content, selected_tool_id, selected_tool_name, tool_description)
                
                nav = console.input(f"\n\n[bold yellow]Press Enter to see another tool or 'q' to return to the main menu: [/]").lower()
                if nav == 'q':
                    break

if __name__ == "__main__":
    main()
