import os
import requests
import math
import time
import click
import inquirer
from rich.console import Console
from rich.table import Table
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
                  box=box.SIMPLE_HEAD , show_lines=True, header_style="bold magenta", show_edge=True)
    
    table.add_column("No.", style="dim", width=4)
    table.add_column("Name", justify="left", width=40, style="bold bright_green")
    table.add_column("Platform", justify="left", width=15, style="bright_cyan")
    table.add_column("Kill Chain Phase", justify="left", width=20, style="bright_yellow")
    table.add_column("Description", overflow="fold", width=160)

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

    threat_actors = get_all_threat_actors(attack_stix_content)

    while True:
        display_title_screen()

        menu_options = [
            'Geographical Region', 
            'Activity Type', 
            'Target Sector', 
            'Exit'
        ]
        questions = [
            inquirer.List('menu',
                          message="Select an option".upper(),
                          choices=menu_options)
        ]
        menu_choice = inquirer.prompt(questions)['menu']

        if menu_choice == 'Exit':
            break

        if menu_choice == 'Geographical Region':
            actor_list = display_threat_actors_by_geo(threat_actors)
        elif menu_choice == 'Activity Type':
            actor_list = display_threat_actors_by_activity(threat_actors)
        elif menu_choice == 'Target Sector':
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

if __name__ == "__main__":
    main()
