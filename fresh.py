from flask import Flask, render_template, request
import os
import pefile
import yara
import peutils
from capstone import *

app = Flask(__name__)

def disassemble_pe(pe_file_path):
    try:
        pe = pefile.PE(pe_file_path)
    except Exception as e:
        print('[!] Error: Could not open PE file:', e)
        return None
    
    try:
        disasm_output = ''
        for section in pe.sections:
            disasm_output += disassemble_section(section.get_data())
        return disasm_output
    except Exception as e:
        print('[!] Error: Disassembly failed:', e)
        return None
    finally:
        pe.close()

def disassemble_section(section_data):
    disasm_output = ''
    try:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        for insn in md.disasm(section_data, 0x1000):
            disasm_output += '0x%x:\t%s\t%s\n' % (insn.address, insn.mnemonic, insn.op_str)
    except Exception as e:
        print('[!] Error: Disassembly of section failed:', e)
    return disasm_output

def extract_pe_info(file_path, yara_rules):
    try:
        pe = pefile.PE(file_path)
        pe_info = {}

        # Basic information
        pe_info['file_path'] = file_path
        pe_info['entry_point'] = f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}"
        pe_info['image_base'] = f"0x{pe.OPTIONAL_HEADER.ImageBase:X}"

        # Sections
        sections = []
        for section in pe.sections:
            sections.append({
                'name': section.Name.decode().strip(),
                'size_of_raw_data': section.SizeOfRawData,
                'characteristics': section.Characteristics
            })
        pe_info['sections'] = sections

        # Imports
        imports = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            entry_dict = {'dll': entry.dll.decode('utf-8'), 'imports': []}
            for imp in entry.imports:
                entry_dict['imports'].append(imp.name.decode('utf-8'))
            imports.append(entry_dict)
        pe_info['imports'] = imports

        # Exports
        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exports.append(exp.name.decode('utf-8'))
        pe_info['exports'] = exports

        # Digital Signature
        pe_info['import_hash'] = pe.get_imphash()

        # YARA Rule Scanning
        yara_matches = []
        rules = yara.compile(filepath=yara_rules)
        matches = rules.match(data=open(file_path, 'rb').read())
        if matches is not None:
            for match in matches:
                yara_matches.append(match.rule)
        pe_info['yara_matches'] = yara_matches

        # Signature-based Detection
        signature_matches = []
        signature_db = peutils.SignatureDatabase()
        matches = signature_db.match(pe, ep_only=True)
        if matches:
            for match in matches:
                signature_matches.append(match[0])
        pe_info['signature_matches'] = signature_matches

        # Data Processing Analysis
        data_processing_info = analyze_data_processing(pe)
        pe_info['data_processing_info'] = data_processing_info

        # Binary Hex Value
        with open(file_path, 'rb') as file:
            binary_data = file.read()
        pe_info['binary_hex'] = ' '.join(f"{byte:02X}" for byte in binary_data)

        # Symbol tree
        symbol_tree = generate_symbol_tree(pe)
        pe_info['symbol_tree'] = symbol_tree

        # Disassembly
        disassembly_output = disassemble_pe(file_path)
        pe_info['disassembly_output'] = disassembly_output

        # API Analyzer
        api_usage = analyze_api_usage(pe)
        pe_info['api_usage'] = api_usage

        # Path Analyzer (Placeholder)
        path_analysis = analyze_path(pe)
        pe_info['path_analysis'] = path_analysis

        return pe_info

    except pefile.PEFormatError as e:
        return {'error': f"Error parsing PE file: {e}"}
    except yara.Error as e:
        return {'error': f"Error in YARA rule compilation: {e}"}

def analyze_data_processing(pe):
    data_processing_info = []

    # Iterate through sections to find sections with executable code
    for section in pe.sections:
        characteristics = section.Characteristics
        # Check if the section contains executable code
        if characteristics & 0x20 != 0:
            section_info = {
                'name': section.Name.decode().strip(),
                'virtual_address': f"0x{section.VirtualAddress:X}",
                'size_of_raw_data': section.SizeOfRawData
            }
            data_processing_info.append(section_info)

            # You can further analyze the code in this section to identify data processing functions or patterns
            # For example, you can use pattern matching or heuristics to identify common data processing functions

    return data_processing_info

def generate_symbol_tree(pe):
    symbol_tree = {}

    # Imported functions
    imported_functions = {}
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode()
        if dll_name not in imported_functions:
            imported_functions[dll_name] = []
        for func in entry.imports:
            imported_functions[dll_name].append(func.name.decode())
    symbol_tree['Imported Functions'] = imported_functions

    # Exported functions
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        exported_functions = []
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exported_functions.append(exp.name.decode())
        symbol_tree['Exported Functions'] = exported_functions

    # Additional sections such as classes, labels, etc. can be added as needed

    return symbol_tree

def analyze_api_usage(pe):
    # Placeholder for API analysis
    # In a real implementation, this function would analyze the usage of APIs in the PE file
    # For demonstration, let's assume some API names
    api_usage = ['LoadLibraryA', 'GetProcAddress', 'CreateProcessA']
    return api_usage

def analyze_path(pe):
    # Placeholder for path analysis
    # In a real implementation, this function would perform path analysis
    # For demonstration, let's return some placeholder data
    path_analysis = {'paths': ['Path 1', 'Path 2', 'Path 3']}
    return path_analysis

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file_path = request.form['file_path']
        yara_rules = request.form['yara_rules']
        
        if os.path.isfile(file_path) and os.path.isfile(yara_rules):
            pe_info = extract_pe_info(file_path, yara_rules)
            return render_template('result.html', pe_info=pe_info)
        else:
            error_message = "Invalid file paths provided."
            return render_template('index.html', error_message=error_message)
    else:
        return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    file_path = request.form['file_path']
    yara_rules = request.form['yara_rules']
    pe_info = extract_pe_info(file_path, yara_rules)

    # Check if there's a search query
    search_query = request.form.get('search_query')
    if search_query:
        # Perform search based on the query
        # For demonstration, let's assume search is performed on the file path
        search_results = [section for section in pe_info['sections'] if search_query in section['name']]

        # Pass the search results to the result.html template
        return render_template('result.html', pe_info=pe_info, search_results=search_results)
    else:
        return render_template('result.html', pe_info=pe_info)

@app.route('/edit', methods=['POST'])
def edit():
    file_path = request.form['file_path']
    offset = int(request.form['offset'], 16)
    new_hex_data = request.form['new_hex_data']

    if os.path.isfile(file_path):
        try:
            # Read the binary data from the file
            with open(file_path, 'rb') as file:
                binary_data = bytearray(file.read())

            # Update the binary data at the specified offset
            for i in range(0, len(new_hex_data), 2):
                byte_value = int(new_hex_data[i:i + 2], 16)
                binary_data[offset + i // 2] = byte_value

            # Write the updated binary data back to the file
            with open(file_path, 'wb') as file:
                file.write(binary_data)

            success_message = f"Binary data at offset {hex(offset)} updated successfully."
            pe_info = extract_pe_info(file_path, "")  # Re-extract PE info after the edit
            return render_template('result.html', pe_info=pe_info, success_message=success_message)
        except Exception as e:
            error_message = f"Error updating binary data: {e}"
            pe_info = extract_pe_info(file_path, "")  # Re-extract PE info after the edit
            return render_template('result.html', pe_info=pe_info, error_message=error_message)
    else:
        error_message = "Invalid file path provided."
        return render_template('result.html', pe_info=pe_info, error_message=error_message)

if __name__ == '__main__':
    app.run(debug=True)
