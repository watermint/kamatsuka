#!/usr/bin/env python3

import re
import sys

def add_path_root_header(file_path):
    """
    Add Dropbox-API-Path-Root header to all relevant endpoints that work with files and content.
    This includes /files/* and /sharing/* endpoints.
    """
    
    # Read the file as text to preserve formatting and comments
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Split content into lines for processing
    lines = content.split('\n')
    
    # Define the Path-Root header parameter
    path_root_header = [
        "      - name: Dropbox-API-Path-Root",
        "        in: header",
        "        description: |-",
        "          Specifies the root namespace for the operation. This allows operations to be performed relative to a specific namespace instead of the default user namespace.",
        "          ",
        "          Supports three modes:",
        "          - Home mode: '{\"tag\": \"home\"}' - roots to user's home namespace",
        "          - Root mode: '{\"tag\": \"root\", \"root\": \"namespace_id\"}' - validates and roots to specific root namespace",
        "          - Namespace mode: '{\"tag\": \"namespace_id\", \"namespace_id\": \"namespace_id\"}' - roots to any accessible namespace",
        "          ",
        "          Essential for accessing team spaces and managing team content. See Path Root Header Modes documentation for details.",
        "        required: false",
        "        content:",
        "          application/json:",
        "            schema:",
        "              oneOf:",
        "                - type: object",
        "                  properties:",
        "                    '.tag':",
        "                      type: string",
        "                      enum: [home]",
        "                  required: ['.tag']",
        "                  example: {'.tag': 'home'}",
        "                - type: object", 
        "                  properties:",
        "                    '.tag':",
        "                      type: string",
        "                      enum: [root]",
        "                    root:",
        "                      type: string",
        "                      description: The namespace ID to validate as root",
        "                  required: ['.tag', 'root']",
        "                  example: {'.tag': 'root', 'root': '123456'}",
        "                - type: object",
        "                  properties:",
        "                    '.tag':",
        "                      type: string", 
        "                      enum: [namespace_id]",
        "                    namespace_id:",
        "                      type: string",
        "                      description: The namespace ID to root operations to",
        "                  required: ['.tag', 'namespace_id']",
        "                  example: {'.tag': 'namespace_id', 'namespace_id': '789012'}"
    ]
    
    # Track modifications
    modifications_made = 0
    current_path = None
    current_method = None
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        # Check if we're starting a new endpoint (path definition)
        path_match = re.match(r'^  (/[^:]*):$', line)
        if path_match:
            current_path = path_match.group(1)
            current_method = None
        
        # Check if we're starting an HTTP method
        method_match = re.match(r'^    (get|post|put|delete|patch|head|options):$', line)
        if method_match:
            current_method = method_match.group(1)
        
        # Check if this endpoint should have the Path-Root header
        if (current_path and current_method and should_add_path_root_header(current_path)):
            
            # Look for the parameters section
            if line.strip() == 'parameters:':
                # Find the position to insert the new header
                # We want to add it after existing headers but before any description
                insert_position = i + 1
                
                # Check if this endpoint already has the Path-Root header
                has_path_root = False
                j = i + 1
                while j < len(lines) and (lines[j].startswith('      ') or lines[j].strip() == ''):
                    if 'Dropbox-API-Path-Root' in lines[j]:
                        has_path_root = True
                        break
                    if lines[j].strip().startswith('description:') and not lines[j].startswith('        '):
                        break
                    j += 1
                
                if not has_path_root:
                    # Insert the Path-Root header after existing parameters
                    # Find the best insertion point (after last parameter)
                    j = i + 1
                    last_param_end = i + 1
                    
                    while j < len(lines):
                        if lines[j].strip().startswith('- name:'):
                            # Found start of a parameter, find its end
                            k = j + 1
                            while k < len(lines) and (lines[k].startswith('        ') or lines[k].strip() == ''):
                                k += 1
                            last_param_end = k
                            j = k
                        elif (lines[j].strip().startswith('description:') and not lines[j].startswith('        ')) or \
                             lines[j].strip().startswith('x-stone-') or \
                             re.match(r'^      [a-zA-Z]', lines[j]):
                            break
                        else:
                            j += 1
                    
                    # Insert the Path-Root header
                    for header_line in path_root_header:
                        lines.insert(last_param_end, header_line)
                        last_param_end += 1
                    
                    modifications_made += 1
                    i = last_param_end - 1  # Adjust loop counter
        
        i += 1
    
    # Write back the modified content
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    
    return modifications_made

def should_add_path_root_header(path):
    """
    Determine if an endpoint should have the Dropbox-API-Path-Root header.
    This includes file operations and sharing operations that work with content.
    """
    # File operations that work with content and paths
    file_patterns = [
        r'^/files/',
        r'^/sharing/',
        r'^/file_properties/'
    ]
    
    # Some endpoints that don't need path root (mostly metadata-only operations)
    excluded_patterns = [
        r'^/files/properties/template/',  # Template operations don't need path root
        r'^/sharing/check_.*_job_status',  # Job status checks don't need path root
        r'^/sharing/list_received_files',  # Listing received files doesn't need path root
    ]
    
    # Check if path matches any excluded pattern
    for pattern in excluded_patterns:
        if re.match(pattern, path):
            return False
    
    # Check if path matches any file pattern
    for pattern in file_patterns:
        if re.match(pattern, path):
            return True
    
    return False

def main():
    if len(sys.argv) != 2:
        print("Usage: python add_path_root_header.py <yaml_file>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    try:
        modifications = add_path_root_header(file_path)
        print(f"Successfully processed {file_path}")
        print(f"Added Dropbox-API-Path-Root headers to {modifications} endpoints")
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()