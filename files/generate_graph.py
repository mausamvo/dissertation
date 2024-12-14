import json
import networkx as nx
from typing import Dict, Set
import os


def build_graph_and_subgraphs(log_file_path: str) -> Dict[str, nx.DiGraph]:
    main_graph = nx.DiGraph()
    file_nodes: Set[str] = set()
    uuid2name = dict()
    file_names = set()

    f, p, s = 0, 0, 0
    
    # Read the entire file content
    with open(log_file_path, 'r') as log_file:
        content = log_file.read()
        
    try:
        # Try parsing as a single JSON array
        print("Attempting to parse as JSON array...")
        log_entries = json.loads(content)
        if not isinstance(log_entries, list):
            log_entries = [log_entries]
            
    except json.JSONDecodeError:
        # If that fails, try parsing line by line
        print("JSON array parsing failed. Attempting to parse line by line...")
        log_entries = []
        for line in content.split('\n'):
            if not line.strip():
                continue
            try:
                # Remove any trailing commas and clean the line
                line = line.strip().rstrip(',').strip()
                if line.startswith('['):
                    line = line[1:]
                if line.endswith(']'):
                    line = line[:-1]
                if line:
                    entry = json.loads(line)
                    log_entries.append(entry)
            except json.JSONDecodeError as e:
                print(f"Warning: Skipping invalid JSON line: {line[:100]}...")
                continue

    # Process all entries for nodes
    for entry in log_entries:
        try:
            datum = entry.get("datum", {})

            if "com.bbn.tc.schema.avro.cdm18.FileObject" in datum:
                file_obj = datum["com.bbn.tc.schema.avro.cdm18.FileObject"]
                file_path = file_obj["baseObject"]["properties"]["map"].get("path")
                if file_path:
                    main_graph.add_node(file_path, type="file")
                    file_nodes.add(file_path)
                    uuid2name[file_obj["uuid"]] = file_path
                    file_names.add(file_path)
                    f += 1

            elif "com.bbn.tc.schema.avro.cdm18.Subject" in datum:
                subject = datum["com.bbn.tc.schema.avro.cdm18.Subject"]
                process_uuid = subject.get("uuid")
                executable_name = subject.get("properties", {}).get("map", {}).get("name")
                if process_uuid and executable_name:
                    main_graph.add_node(executable_name, type="process")
                    uuid2name[process_uuid] = executable_name
                    p += 1

            elif "com.bbn.tc.schema.avro.cdm18.NetFlowObject" in datum:
                netflow_obj = datum["com.bbn.tc.schema.avro.cdm18.NetFlowObject"]
                socket_address = netflow_obj.get("remoteAddress")
                if socket_address:
                    main_graph.add_node(socket_address, type="socket")
                    uuid2name[netflow_obj["uuid"]] = socket_address
                    s += 1

        except Exception as e:
            print(f"Error processing entry: {str(e)}")
            continue

    # Process all entries for edges
    for entry in log_entries:
        try:
            datum = entry.get("datum", {})
            if "com.bbn.tc.schema.avro.cdm18.Event" in datum:
                event = datum["com.bbn.tc.schema.avro.cdm18.Event"]
                syscall = event.get("type")
                subject = event.get("subject", {})
                src = subject.get("com.bbn.tc.schema.avro.cdm18.UUID")
                preobject = event.get("predicateObject", {})
                tgt = preobject.get("com.bbn.tc.schema.avro.cdm18.UUID")

                if src in uuid2name and tgt in uuid2name:
                    name1 = uuid2name[src]
                    name2 = uuid2name[tgt]
                    if name2 in file_names:
                        main_graph.add_edge(name2, name1, syscall=syscall)
                    else:
                        main_graph.add_edge(name1, name2, syscall=syscall)

        except Exception as e:
            print(f"Error processing entry for edges: {str(e)}")
            continue

    print(f"file: {f}, process: {p}, socket: {s}")
    print(f"main graph nodes: {len(main_graph.nodes)}, edges: {len(main_graph.edges)}")

    file_subgraphs = {}
    for file_node in file_nodes:
        descendants = nx.descendants(main_graph, file_node)
        subgraph_nodes = {file_node} | descendants
        file_subgraphs[file_node] = main_graph.subgraph(subgraph_nodes).copy()

    return main_graph, file_subgraphs

def save_graph_as_gml(subgraph, output_path, graph_index):
    """
    Save the graph in GML format.
    """
    gml_file = os.path.join(output_path, f"graph{graph_index}.gml")
    nx.write_gml(subgraph, gml_file)
    print(f"Saved GML file to {gml_file}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python graph_builder.py <log_file_path>")
        sys.exit(1)

    log_file = sys.argv[1]

    # Create output directory if it doesn't exist
    output_dir = "output#"
    os.makedirs(output_dir, exist_ok=True)

    main_graph, behaviors = build_graph_and_subgraphs(log_file)
    print(f"behaviors: {len(behaviors)}")

    for i, (file_path, behavior) in enumerate(behaviors.items(), start=1):
        print(f"Processing subgraph {i}: nodes={len(behavior.nodes)}, edges={len(behavior.edges)}")
        save_graph_as_gml(behavior, output_dir, i)

