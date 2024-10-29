import frida
import argparse
import sys
import os
import signal
import json

import configparser
import re
from pathlib import Path

'''
// Module info
'''
class Module:
    def __init__(self, name, base, size, path):
        self.name = name
        self.base = base
        self.size = size
        self.path = path

class AllModules:
    def __init__(self):
        self.modules = {}

    def add_module(self, module_dict):
        name = module_dict['name']  # Extract name with extension
        base = int(module_dict['base'], 16)  # Convert hex base to integer
        size = module_dict['size']  # Assuming size is already an int
        module = Module(name, base, size, module_dict['path'])
        self.modules[name] = module
        # Sort the modules based on the base address
        self.modules = dict(sorted(self.modules.items(), key=lambda x: x[1].base))

    def __getattr__(self, name): 
        return self.modules.get(name)
    
    def __getitem__(self, name): 
        return self.modules.get(name)
        
    def find_module_by_address(self, address):
        # Binary search to find the module
        low = 0
        high = len(self.modules) - 1
        # print("high:", high)
        while low <= high:
            mid = (low + high) // 2
            module = list(self.modules.values())[mid]
            # print(module.name, hex(module.base), hex(address), hex(module.base + module.size));
            if module.base <= address <= module.base + module.size:
                # print("return:", module.name)
                return module   # returns the module object, not the name!
            elif address < module.base:
                high = mid - 1
            else:
                low = mid + 1
        return None  # Address not found in any module


'''
// Parse the received data
'''
def parse_modules(module_obj):
    global all_modules_obj
    all_modules_obj.add_module(module_obj)

def parse_exports(result):    
    global allExports    
    name_address_dict = {item["address"]: item["name"] for item in result[1]} #export name - address mapping
    allExports[result[0]] = name_address_dict
    # As of now we are not dumping exports to a file.
    # with open('[out]exports.log', 'a') as f:
        # json.dump(result, f, indent=2)
        # f.write("\n")

def find_export_name_by_address(allExports, dll_name, target_address):
    return allExports.get(dll_name, {}).get(target_address)

def parse_events(allEvents):
    handlers = {
        "compile": compile_handler,
        "call": call_handler
        # "exec": exec_handler,
        # "ret": ret_handler,
        # "block": block_handler
    }

    for event in allEvents:
        event_type = event[0]
        if event_type in handlers:
            handler = handlers[event_type]
            handler(event)
        else:
            print("Unknown event type:", event_type)

# 'compile' events are primarily used for basic block tracing. 
def compile_handler(event): # Example: ["compile", "0x77485060", "0x77485069"]
    # Logic for handling compile events
    # print("Compile event:", event)
    # pass
    bb_handler(event)
    pass

def bb_handler(event):
    global all_modules_obj
    global all_compile_events_list

    bbModule = all_modules_obj.find_module_by_address(int(event[1],0)); #bbModule is a Module object.    
    if bbModule is None:
        event_str = f"[None] {event[1]} , {event[2]} [None]\n"
    else:
        # event_str = f"[{bbModule.name}] {event[0]} , {event[1]} [{bbModule.name}]\n"  # Absolute addresses
        event_str = f"[{bbModule.name}] {hex(int(event[1],0) - bbModule.base)} , {hex(int(event[2],0) - bbModule.base)} [{bbModule.name}]\n"  # Relative addresses
        
    all_compile_events_list.append(event_str)

def call_handler(event):    # Example: ["call", "0x77477b26", "0x77497e44", 1]
    # # Logic for handling call events
    # print("Call event:", event)
    # pass
    global all_call_events_list

    event_str = addr_handler(event)
    all_call_events_list.append(event_str)


# Parse syscall event
def parse_syscall_event(event): # [currMnemonic, currAddr, rsp_ret, syscall_id, arg0, arg1, arg2, arg3, JSON.stringify(context)]
    fromModule = all_modules_obj.find_module_by_address(int(event[1],0))
    toModule = all_modules_obj.find_module_by_address(int(event[2],0))
    
    syscall_id = int(event[3],0)
    syscall_name = syscall_id_to_name[syscall_id]
    
    if toModule is None:
        if fromModule is None:
            event_str = (f"[None] {event[1]} , {event[0]} {event[2]} [None], syscall_id: {event[3]}, syscall_name: {syscall_name}, arg0(rcx): {event[4]}, arg1(rdx): {event[5]}, arg2(r8): {event[6]}, arg3(r9): {event[7]}, full_context: {event[8]} \n")
        else:
            event_str = (f"[{fromModule.name}] {hex(int(event[1],0) - fromModule.base)} , {event[0]} {event[2]} [None] , syscall_id: {event[3]}, syscall_name: {syscall_name}, arg0(rcx): {event[4]}, arg1(rdx): {event[5]}, arg2(r8): {event[6]}, arg3(r9): {event[7]}, full_context: {event[8]} \n")
    else:
        if fromModule is None:
            event_str = (f"[None] {event[1]} , {event[0]} {hex(int(event[2],0) - toModule.base)} [{toModule.name}] , syscall_id: {event[3]}, syscall_name: {syscall_name},  arg0(rcx): {event[4]}, arg1(rdx): {event[5]}, arg2(r8): {event[6]}, arg3(r9): {event[7]}, full_context: {event[8]} \n")
        else:
            event_str = (f"[{fromModule.name}] {hex(int(event[1],0) - fromModule.base)} , {event[0]} {hex(int(event[2],0) - toModule.base)} [{toModule.name}] , syscall_id: {event[3]}, syscall_name: {syscall_name}, arg0(rcx): {event[4]}, arg1(rdx): {event[5]}, arg2(r8): {event[6]}, arg3(r9): {event[7]}, full_context: {event[8]} \n")            
    
    return event_str


# If a event is in the form [addr1, addr2, .....]. If you want to resovle the called export.
def addr_handler(event):
    global all_modules_obj
    global allExports    

    if event[0] == 'syscall':
        event_str = parse_syscall_event(event)
        return event_str
    
    fromModule = all_modules_obj.find_module_by_address(int(event[1],0))
    toModule = all_modules_obj.find_module_by_address(int(event[2],0))

    if toModule is None: 
        if fromModule is None:
            event_str = (f"[None] {event[1]} , {event[0]} {event[2]} [None] {event[0]} {event[3]}\n")
        else:
            event_str = (f"[{fromModule.name}] {hex(int(event[1],0) - fromModule.base)} , {event[0]} {event[2]} [None] {event[0]} {event[3]}\n")
    else:
        exp_name = find_export_name_by_address(allExports, toModule.name, event[2]) #we are directly matching the address as string with the dictionary key.
        if exp_name == None:
            if fromModule is None:
                event_str = (f"[None] {event[1]} , {event[0]} {hex(int(event[2],0) - toModule.base)} [{toModule.name}] {event[0]} {event[3]}\n")
            else:
                event_str = (f"[{fromModule.name}] {hex(int(event[1],0) - fromModule.base)} , {event[0]} {hex(int(event[2],0) - toModule.base)} [{toModule.name}] {event[0]} {event[3]}\n")
        else:
            if fromModule is None:
                event_str = (f"[None] {event[1]} , {event[0]} {hex(int(event[2],0) - toModule.base)} [{toModule.name}->{exp_name}] {event[0]} {event[3]}\n")
            else:
                event_str = (f"[{fromModule.name}] {hex(int(event[1],0) - fromModule.base)} , {event[0]} {hex(int(event[2],0) - toModule.base)} [{toModule.name}->{exp_name}] {event[0]} {event[3]}\n")

    return event_str


collected_apis = []

def parse_api(api_event):
    global all_modules_obj
    
    fromModule = all_modules_obj.find_module_by_address(int(api_event["retnaddr"],0));
    
    if fromModule is None:
        api_event["retnaddr"] = "None " + api_event["retnaddr"]
    else:
        api_event["retnaddr"] = fromModule.name + "+" + hex(int(api_event["retnaddr"],0) - fromModule.base)
    
    return api_event

def parse_apis(api_events):    
    for api_event in api_events:
        parse_api(api_event)
        
    
    # return api_events

'''
// Receive the info from frida javascript client side.
'''
# receive the data
def on_message(message, data): 
    # global grecvd
    if message['type'] == 'send':
        # print("[*] Message from script:", message['payload'])
        process_recvd_data(message['payload']['recvd_cmd'], message['payload']['result'])
    else:
        print(message)

# my_count = 0
# deal with the received data
def process_recvd_data(command, result):
    if command == 'modules&exports':
        # When we send multiple items, they will be received as a 'list'.
        # Slicing the list to extract first item. The output is also a list.
        part1 = result[0:1]
        # Slicing the list to extract remaining items. The output is also a list.
        part2 = result[1:]
        parse_modules(part1[0]) # parse_modules() expects a dictionary. So, we extract our dictionary from the single list item.
        parse_exports(part2)    # parse_exports() expects a list. so, we send part2 directly.
        
    if command == 'events':
        parse_events(result)

    if command == 'instruction':
        collect_dyn_instructions(result)
        # parse_dyn_instructions(result)
        # parse_instructions(result)
        # global my_count
        # my_count = my_count +1
        # print("my_count:",my_count,"\n")
        # with open('[out]instructions.log', 'a') as f:
            # json.dump(result, f, indent=2)
            # f.write("\n")        

    if command == 'api':
        global collected_apis
        print(result)
        collected_apis.append(result)
        
        # result = parse_api(result)
        # print(result["retnaddr"])
        # with open('[out]api.log', 'a') as f:
            # # json.dump(result, f, indent=2)
            # json.dump(result, f)
            # f.write("\n")
            
    if command == 'test':
        with open('[out]test.log', 'a') as f:
            json.dump(result, f, indent=2)
            # json.dump(result, f)
            f.write("\n")   

def parse_dyn_instructions(dynEvents):
    global all_dyncalls_list
    
    for event in dynEvents:
        # print(event)
        event_str = addr_handler(event)
        all_dyncalls_list.append(event_str)        
        
    
def collect_dyn_instructions(dynEvents):
    global crude_dyncalls_list

    for event in dynEvents:
        crude_dyncalls_list.append(event)




'''
// Save the processed data to file
'''
def write_header(filename):
    global all_modules_obj
    
    with open(filename, 'w') as file:
        header_section_start = "* ======================== HEADER START ========================= *\n"
        file.write(header_section_start)
        
        header = "* {:<20}\t{:<12}\t{:<12}\t{}\n".format("Module_Name", "Module_Base", "Module_Size", "Module_Path")
        file.write(header)
        design_line = "* -----------------------------------------------------------------\n"
        file.write(design_line)
        
        for module in all_modules_obj.modules.values():
            line = "* {:<20}\t{:<12}\t{:<12}\t{}\n".format(module.name, hex(module.base), hex(module.size), module.path)
            file.write(line)
        
        header_section_end = "* ========================= HEADER END ========================== *\n"
        file.write(header_section_end)     


def write_events(filename, events_list):
    with open(filename, 'a') as f:
        f.writelines(events_list)

def write_api(filename, result):
    with open(filename, 'a') as f:
        # json.dump(result, f, indent=2)
        # json.dump(result, f)
        # f.write("\n")
        for api_event in result:
            f.write(str(api_event))
            f.write("\n")


def save_trace(bbtrace_f, calltrace_f, dyncalls_f, apis_f):
    global all_compile_events_list
    global all_call_events_list
    global all_dyncalls_list
    global crude_dyncalls_list
    global collected_apis
    
    
    with open("dyn_api.log", 'a') as f:
        json.dump(crude_dyncalls_list, f)
        f.write("\n")       
    
    
       
    parse_dyn_instructions(crude_dyncalls_list)    
    # print(type(collected_apis))
    # print(type(all_call_events_list))
    parse_apis(collected_apis)
    # print(collected_apis)
    
    write_header(bbtrace_f)
    print("[+] Successfully written Header (containing module info)")
    write_events(bbtrace_f, all_compile_events_list)
    print("[+] Sucessfully written Basic Blocks Trace")
    
    write_header(calltrace_f)    
    print("[+] Successfully written Header (containing module info)")
    write_events(calltrace_f, all_call_events_list)
    print("[+] Sucessfully written Call Trace")

    write_header(dyncalls_f)    
    print("[+] Successfully written Header (containing module info)")
    write_events(dyncalls_f, all_dyncalls_list)
    print("[+] Sucessfully written Dynamic Calls")
    
    write_header(apis_f)
    print("[+] Successfully written Header (containing module info)")
    write_api(apis_f, collected_apis)
    print("[+] Sucessfully written API data")
    
    # write_events(apis_f, collected_apis)

'''
// Terminate the process after saving the data.
'''
def kill_process(pid):
    try:
        os.kill(pid, signal.SIGTERM)  # Force kill the process
        print(f"Process with PID {pid} terminated successfully.")
    except OSError as e:
        print(f"Failed to terminate process with PID {pid}: {e}")


'''
//  Global variables
'''
all_modules_obj = AllModules()  # To hold details about all the loaded modules in the process.
all_compile_events_list = []    # To hold all the processed basic block events.
all_call_events_list = []       # To hold all the processed call events.
allExports = {}                 # To hold all exports
all_dyncalls_list = []          # To hold all the processed dynamic call events.
crude_dyncalls_list = []        # To hold all the crude dynamic call events.

# def your_function(script):
    # print("Process exited!\n")
    # script.exports_sync.callgetleftoverevents("1")



def get_api_names_from_ini(config):
    api_names = []
    if 'API_MONITOR' in config:
        for key, value in config['API_MONITOR'].items():
            value = value.strip().lower() if value else None
            if value in ("true", "yes", "1"):
                api_names.append(key)
    
    return api_names

def extract_functions(directory_path, api_names):
    # Dictionary to store functions enclosed in //support tags
    functions_dict = {}
    # Variable to store remaining content of files
    remaining_content = ""

    # Iterate over files in the directory
    for root, dirs, files in os.walk(directory_path):
        for file_name in files:
            if file_name.endswith(".js") and os.path.splitext(file_name)[0] in api_names:
                file_path = os.path.join(root, file_name)
                with open(file_path, 'r') as file:
                    file_content = file.read()

                # Extract content between //support tags
                matches = re.findall(r'//support\n(.*?)\n//support', file_content, re.DOTALL)
                for match in matches:
                    # Store function content in the dictionary
                    functions_dict[match.strip()] = None

                # Extract remaining content from the file
                remaining_content += re.sub(r'//support\n(.*?)\n//support', '', file_content, flags=re.DOTALL)

    return functions_dict, remaining_content

def generate_api_code(directory_path, settings, api_names):
    api_code = ""

    # API Monitor section
    if 'API_MONITOR' in settings:
        API_MONITOR_settings = settings['API_MONITOR']
        api_code += "// API Monitor\n"
        
    # Extract functions enclosed in //support tags and remaining content from specific files
    functions_dict, remaining_content = extract_functions(directory_path, api_names)

    # Remove //support tags from the functions dictionary
    functions_dict = {function_content.strip("//support\n").strip("//support"): None for function_content in functions_dict}
 
    api_code = remaining_content
    # print(api_code)
    
    for function_content in functions_dict.keys():
        # print(function_content)
        api_code += function_content + "\n\n"
         
    # print(api_code)
    return api_code

def generate_js_code(directory_path, settings, api_names):
    js_code = ""

    # Top part of the loop
    js_code += """

const INSTRUCTION_THRESHOLD = 10000; // I think I might lose events with this method for the last iteration?! Yeah, you are correct but we are using rpc.exports.dispose to send the remaining buffe when the program gets exited.



var allModuleNames = []; // track all the loaded modules

const update_module_list = () => {
    
    const currModules = Process.enumerateModules();
    
    // Get the names of current modules from currModules
    var currModuleNames = [];
    for (var count=0; count<currModules.length; count++)
    {
        currModuleNames.push(currModules[count].name);
    }
    
    currModuleNames.forEach(currModuleName => {
        if (!allModuleNames.includes(currModuleName)) { 
            allModuleNames.push(currModuleName); // If a new module is found, add it to the allModuleNames
            // console.log(currModuleName);
            send({"recvd_cmd": "modules&exports", result: [Process.findModuleByName(currModuleName), currModuleName, Module.enumerateExports(currModuleName)]});      // When you use [], the payload will be sent as a list. Otherwise, the 'data type' is determined based on the structure of the data.
            
        }
    });
};

update_module_list();

var instructionBuffer = []; // Buffer to store instructions before sending

const mainThread = Process.enumerateThreads()[0];     


// Loop setup
Stalker.follow(mainThread.id, {\n"""


    # General options handling
    
    events = {
        'trace_all_calls': 'call',
        'trace_all_rets': 'ret',
        'trace_all_executed_instructions': 'exec',
        'trace_coarse_blocks': 'block',
        'trace_basic_blocks': 'compile'        
    }

    event_lines = []
    for key, event in events.items():
        event_lines.append(f"\t\t{event}: {str(settings['GENERAL'].getboolean(key, False)).lower()}")

    # what type of events to receive
    js_code += "\tevents: {\n" + ",\n".join(event_lines) + "\n\t},\n"
    
    # do something with the received events
    js_code +="""
	onReceive: function(events) {
		var allEvents = Stalker.parse(events, {
			annotate: true,
			stringify: true
		});

		// Update module list or any other necessary actions
		update_module_list();

		// Send combinedEvents
		send({ "recvd_cmd": "events", result: allEvents });		
	}, 
    """
    
    js_code +="""
    transform: function(iterator) {
        let instruction = iterator.next();
		do{			
			
            let currAddr = instruction.address;
			let currMnemonic = instruction.mnemonic;
			let currOpStr = instruction.opStr;\n"""

    # Dynamic calls handling
    if settings['GENERAL'].getboolean('trace_dynamic_calls', False):
        js_code += """
			// resolving dynamic calls
            if (instruction.mnemonic == 'call') {				
				if (instruction.operands[0].type == 'mem'){
					//console.log(JSON.stringify(instruction, null, 4));
					// console.log(instruction.operands[0].value['disp']);
			
					if (instruction.operands[0].value['base']){	// addr relative to a register. Ex: call dword ptr [ebx + 0xc]
						let usedreg = instruction.operands[0].value['base'];
						let offsetvalue = instruction.operands[0].value['disp'];
                        let opSize = 0;
                        if (usedreg == 'rip') // Ex: call qword ptr [rip + 0x19a56d]   In these cases, you need to count the size of instruction also.
                        {
                            opSize = instruction.size;
                        }
                        
						//console.log("reg:", usedreg,"disp:", offsetvalue, "opSize:", opSize);
						
						iterator.putCallout(function(context) {					
							let total = parseInt(context[usedreg]) + parseInt(offsetvalue) + parseInt(opSize);
							//total = '0x' + total.toString(16);
							//console.log("reg:",usedreg, context[usedreg], "total:", total);
							let toPtr = '0x' + ptr(total).readPointer().toString(16);
							//console.log(currMnemonic, currAddr, toPtr, currOpStr);
							instructionBuffer.push([currMnemonic, currAddr, toPtr, currOpStr]);
						});
						// console.log(JSON.stringify(instruction, null, 4));
						
					}
					else{	// direct address. Ex: call dword ptr [0x76231245]		--- usually seen only in 32bit code. Not seen in 64bit code.			
						let outvalue = '0x' + instruction.operands[0].value['disp'].toString(16);
						let finapPtr = '0x' + ptr(outvalue).readPointer().toString(16);
						//console.log(currMnemonic, currAddr, finapPtr, currOpStr);
						instructionBuffer.push([currMnemonic, currAddr, finapPtr, currOpStr]);
						
					}					
				}
				else if (instruction.operands[0].type == 'reg'){ // Ex: call esi
					iterator.putCallout(function(context) {
						instructionBuffer.push([currMnemonic, currAddr, context[currOpStr], currOpStr]);
					});			
					
				}
			}\n"""

    # Dynamic jmps handling
    if settings['GENERAL'].getboolean('trace_dynamic_jmps', False):
        js_code +="""
            // resolving dynamic jmps
            if (instruction.mnemonic == 'jmp') {					
                if (instruction.operands[0].type == 'mem'){
                     //console.log(JSON.stringify(instruction, null, 4));
                    // console.log(instruction.operands[0].value['disp']);
            
                    if (instruction.operands[0].value['base']){
						let usedreg = instruction.operands[0].value['base'];
						let offsetvalue = instruction.operands[0].value['disp'];
                        let opSize = 0;
                        if (usedreg == 'rip') // Ex: call qword ptr [rip + 0x19a56d]   In these cases, you need to count the size of instruction also.
                        {
                            opSize = instruction.size;
                        }
                        
						//console.log("reg:", usedreg,"disp:", offsetvalue, "opSize:", opSize);
						
						iterator.putCallout(function(context) {					
							let total = parseInt(context[usedreg]) + parseInt(offsetvalue) + parseInt(opSize);
							//total = '0x' + total.toString(16);
							//console.log("reg:",usedreg, context[usedreg], "total:", total);
							let toPtr = '0x' + ptr(total).readPointer().toString(16);
							//console.log(currMnemonic, currAddr, toPtr, currOpStr);
							instructionBuffer.push([currMnemonic, currAddr, toPtr, currOpStr]);
						});
						// console.log(JSON.stringify(instruction, null, 4));                        
                    }                    
                    else if (instruction.operands[0].value['index']){	// addr relative to a register. Ex: jmp dword ptr [ebx*2 + 0x7c431223]
                        let usedreg = instruction.operands[0].value['index']
                        let usedscale = instruction.operands[0].value['scale']
                        let offsetvalue = instruction.operands[0].value['disp']
                        
                        //console.log("reg:", usedreg,"disp:", offsetvalue);
                        
                        let opSize = 0;
                        if (usedreg == 'rip') // Ex: call qword ptr [rip + 0x19a56d]   In these cases, you need to count the size of instruction also.
                        {
                            opSize = instruction.size;
                        }                        
                        
                        
                        iterator.putCallout(function(context) {					
                            let total = parseInt(context[usedreg])*parseInt(usedscale) + parseInt(offsetvalue) + parseInt(opSize) ;
                            total = '0x' + total.toString(16);
                            //console.log("reg:",usedreg, context[usedreg], "total:", total);
                            let toPtr = '0x' + ptr(total).readPointer().toString(16);
                            //console.log(currMnemonic, currAddr, toPtr, currOpStr);
                            instructionBuffer.push([currMnemonic, currAddr, toPtr, currOpStr]);
                        });
                        // console.log(JSON.stringify(instruction, null, 4));
                        
                    }
                    else{	// direct address. Ex: jmp dword ptr [0x76231245]					
                        let outvalue = '0x' + instruction.operands[0].value['disp'].toString(16);
                        let finapPtr = '0x' + ptr(outvalue).readPointer().toString(16);
                        // console.log(currMnemonic, currAddr, finapPtr, currOpStr);
                        instructionBuffer.push([currMnemonic, currAddr, finapPtr, currOpStr]);
                        
                    }				
                }
                else if (instruction.operands[0].type == 'reg'){ // Ex: jmp esi
                    iterator.putCallout(function(context) {
                        instructionBuffer.push([currMnemonic, currAddr, context[currOpStr], currOpStr]);
                    });
                }					
            }\n"""

    # Syscall tracing
    if settings['GENERAL'].getboolean('trace_syscalls', False):
        js_code += """
            // Syscall tracing code
            if (instruction.mnemonic == 'syscall') {
                

                
                
                // Your syscall tracing code goes here
                iterator.putCallout(function(context) {
                    let syscall_id = context.rax;
                    let arg0 = context.rcx;
                    let arg1 = context.rdx;
                    let arg2 = context.r8;
                    let arg3 = context.r9;
                    let rsp_ret = context.rsp;
                    
                    instructionBuffer.push([currMnemonic, currAddr, rsp_ret.readPointer(), syscall_id, arg0, arg1, arg2, arg3, JSON.stringify(context)]);
                });
                
                
                instruction = iterator.next();
                console.log(JSON.stringify(instruction, null, 4));                
                
                
                
            }\n"""

    # send the collected instructions
    js_code +="""
			// send the collected instructions
			if (instructionBuffer.length >= INSTRUCTION_THRESHOLD){ 
				// Stalker.flush(); // need to check if this is the correct way to use Stalker.flush()
				
				send({ "recvd_cmd": "instruction", result: instructionBuffer });
				instructionBuffer = []; // Clear the buffer after sending
				
			}\n"""    
      
    # Bottom part of the loop
    js_code += """
            iterator.keep();
        } while ((instruction = iterator.next()) != null);
    },
    
});\n\n

// To send the final leftover events.
rpc.exports = {
  dispose() {

        if (instructionBuffer.length > 0){ 
        // Stalker.flush(); // need to check if this is the correct way to use Stalker.flush()
        
        send({ "recvd_cmd": "instruction", result: instructionBuffer });
        instructionBuffer = []; // Clear the buffer after sending
        console.log("rpc.exports.dispose() successfully sent remaining events.\\n");
        
        }
        else{
            console.log("Nothing to send, buffer is empty.\\n")
        }
  },
  
};\n\n   

"""

    # Include API monitor code
    js_code += generate_api_code(directory_path, settings, api_names)

    return js_code

'''
    syscall generation code
'''
import pefile
import struct
import platform
import pickle

syscall_name_to_id = {} # dict
syscall_id_to_name = {} # dict

def is_syscall_stub(code):
    # Check if the code matches the syscall stub pattern
    return (
        len(code) >= 24 and
        code[0:4] == b'\x4C\x8B\xD1\xB8' and
        code[8:11] == b'\xF6\x04\x25' and
        code[16:24] == b'\x75\x03\x0F\x05\xC3\xCD\x2E\xC3'
    )

def extract_syscall_id(code):
    # Extract syscall ID from the code
    syscall_id = struct.unpack('I', code[4:8])[0]  # Assuming syscall id is a 4-byte little-endian integer
    return syscall_id

def parse_sys_exports():
    syscall_name_to_id  # Dictionary to store syscall names and IDs
    syscall_id_to_name  # Dictionary to store syscall IDs and names
    
    dll_paths = ["C:\\Windows\\System32\\ntdll.dll", "C:\\Windows\\System32\\win32u.dll"]  # Change this path accordingly
    for dll_path in dll_paths:
        try:
            pe = pefile.PE(dll_path)
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                export_table = pe.DIRECTORY_ENTRY_EXPORT.symbols

                for exp in export_table:
                    if exp.address:
                        export_offset = pe.get_offset_from_rva(exp.address)
                        code = pe.get_data(exp.address, 24)
                        if is_syscall_stub(code):
                            syscall_id = extract_syscall_id(code)
                            syscall_name = exp.name.decode() if exp.name else 'No Name'
                            syscall_name_to_id[syscall_name] = syscall_id
                            syscall_id_to_name[syscall_id] = syscall_name

        except Exception as e:
            print(f"Error: {e}")
    
    return syscall_name_to_id, syscall_id_to_name

# Usage:
# syscall_id_to_name[0xf]   or    syscall_id_to_name[15]     # You can directly use an int or hex value as key. The output string could be Nt* or Zw*.
# syscall_name_to_id['NtClose']    or    syscall_name_to_id['ZwClose']      # The output is an integer. You may need to convert to hex or string if needed.

def save_to_disk(filename, data):
    with open(filename, 'wb') as f:
        pickle.dump(data, f)

def load_from_disk(filename):
    with open(filename, 'rb') as f:
        return pickle.load(f)

def get_os_version_info():
    # Get OS information
    return f"{platform.system()} {platform.release()} {platform.version()}"

def check_os_version(os_version_file):
    if os.path.exists(os_version_file):
        stored_os_version = load_from_disk(os_version_file)
        current_os_version = get_os_version_info()
        return stored_os_version == current_os_version
    return False


def generate_syscall_ids():
    global syscall_name_to_id
    global syscall_id_to_name   
    
    name_to_id_file = 'syscall_name_to_id.pkl'
    id_to_name_file = 'syscall_id_to_name.pkl'
    os_version_file = 'os_version.pkl'

    # Check if the dictionaries already exist on disk and if the OS version is the same
    if os.path.exists(name_to_id_file) and os.path.exists(id_to_name_file) and check_os_version(os_version_file):
        print("Loading syscall dictionaries from disk...")
        syscall_name_to_id = load_from_disk(name_to_id_file)
        syscall_id_to_name = load_from_disk(id_to_name_file)
    else:
        print("Generating syscall dictionaries...")
        syscall_name_to_id, syscall_id_to_name = parse_sys_exports()
        # Save the generated dictionaries to disk
        save_to_disk(name_to_id_file, syscall_name_to_id)
        save_to_disk(id_to_name_file, syscall_id_to_name)
        # Save the current OS version to disk
        save_to_disk(os_version_file, get_os_version_info())
    
    # Print OS info
    print("OS Info:")
    print(f"[{get_os_version_info()}]\n")       

def main():
    try:
        output_bbtrace_file = '[out]bb_trace.log'
        output_calltrace_file = '[out]call_trace.log'
        output_dyncalls_file = '[out]dynamic_calls.log'
        output_api_file = '[out]api.log'
        
        # javascript instrumentation logic file
        _SCRIPT_FILE = 'tracer_logic.js'
        
        # read the tracer logic into a variable
        # # with open(_SCRIPT_FILE, 'r') as script_file:
            # # code = script_file.read()


        # Define the directory path
        directory_path = "frida_interceptor_scripts" #api_definitions

        ini_file = "frida_settings.ini"
        
        # Initialize the parser and read the .ini file
        config = configparser.ConfigParser(allow_no_value=True)
        # Preserve case of keys. VirtualProtect instead of virtualprotect.
        config.optionxform = str
        # Read the config file
        config.read(ini_file)

        # print("Frida Settings:")
        # for section in config.sections():
            # print(f"[{section}]")
            # for key, value in config.items(section):
                # print(f"{key}: {value}")

        settings = {}
        for section in config.sections():
            # print(f"Section: {section}")
            for key, value in config[section].items():
                value = value.strip().lower() if value else None
                if value in ("true", "yes", "1"):
                    settings[key.strip()] = True
                elif value in ("false", "no", "0"):
                    settings[key.strip()] = False
                    
        print("\nFrida Settings:")        
        for key, value in settings.items():
            print(f"{key}: {value}")
        
        if (settings['trace_syscalls'] == True):
            generate_syscall_ids()              
        
        
        # Get API names from the .ini file
        api_names = get_api_names_from_ini(config)   
        
        # Generate JS code
        code = generate_js_code(directory_path, config, api_names)           

        # parse the command line parameters
        parser = argparse.ArgumentParser(description='Frida script to trace execution of an executable.')
        parser.add_argument('parameters', nargs='+')
        args = parser.parse_args()
        # print(args)

        # create the process in suspended mode
        device = frida.get_local_device()
        pid = device.spawn(args.parameters) # We are first creating a device and then using spawn. If we directly use frida.spawn(), then we cant see the errors in our javascript instrumentation script. It will just fail if there are errors without any error messages.
        print('pid: %d' % pid)

        # attach frida instrumentaion engine to the suspended process
        session = device.attach(pid)

        # inject the instrumentation code into the process.
        script = session.create_script(code)
        script.on('message', on_message)

        script.load()
        # script.exports_sync.callgetleftoverevents("1")

        # start the execution of process
        device.resume(pid)

        print("Press 'CTRL+C' to stop execution and save the trace.")
        sys.stdin.read()
        
        session.detach()

    except KeyboardInterrupt:        
        # script.exports_sync.callgetleftoverevents("1")
        print(f"[*] Writing all the trace data .....")
        save_trace(output_bbtrace_file, output_calltrace_file, output_dyncalls_file, output_api_file)
        print("[*] Ending the process ...")
        kill_process(pid)  # Force kill the process

if __name__ == '__main__':
    main()