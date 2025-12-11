import os
import sys
import subprocess
import argparse
import operator
import re
from termcolor import colored
from typing import List, TypedDict, Annotated, Optional

import yaml

from dotenv import load_dotenv

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import PromptTemplate
from pydantic import BaseModel, Field
from langchain.tools import tool
from langgraph.graph import StateGraph, END

load_dotenv()

class WriteScriptInput(BaseModel):
    filename: str = Field(description="The name of the Python script file to create, e.g., 'solve.py'.")
    code: str = Field(description="The complete Python code to write into the file.")

class ExecuteScriptInput(BaseModel):
    filename: str = Field(description="The name of the Python script to execute.")

@tool(args_schema=WriteScriptInput)
def write_python_script(filename: str, code: str) -> str:
    """Writes a complete, standalone Python script to a file."""
    try:
        cleaned_code = clean_python_code(code)
        with open(filename, 'w') as f:
            f.write(cleaned_code)
        print(colored(f"--- TOOL: Wrote {len(cleaned_code)} bytes to {filename} ---", "yellow"))
        return f"Successfully wrote script to '{filename}'."
    except Exception as e:
        return f"Error writing script: {e}"

@tool(args_schema=ExecuteScriptInput)
def execute_script(filename: str) -> str:
    """Executes a Python script and captures its output."""
    try:
        print(colored(f"--- TOOL: Executing {filename} ---", "yellow"))
        python_executable = sys.executable
        command = [python_executable, filename]
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        output = f"--- STDOUT ---\n{result.stdout}\n"
        if result.stderr:
            output += f"--- STDERR ---\n{result.stderr}\n"
        return output
    except Exception as e:
        return f"An unexpected error occurred during execution: {e}"


class ServiceInfo(BaseModel):
    """Holds information about a single service from docker-compose."""
    name: str = Field(description="The name of the service (e.g., 'web', 'api').")
    url: str = Field(description="The full URL to access the service (e.g., 'http://localhost:8080').")

class VulnerableEndpoint(BaseModel):
    """Describes a single vulnerable endpoint."""
    service_name: str = Field(description="The name of the service this endpoint belongs to (e.g., 'web', 'api').")
    path: str = Field(description="The relative path of the vulnerable endpoint (e.g., '/login', '/api/v1/search', '/user/1'). For IDOR, this might be the path template.")
    method: str = Field(description="The HTTP method used to interact with the endpoint (e.g., 'GET', 'POST', 'PUT').")
    parameters: List[str] = Field(description="A list of parameters that are identified as vulnerable (e.g., 'username', 'search_query', 'id').")
    is_json_payload: bool = Field(description="Set to true if the payload for a POST/PUT request should be sent as JSON, otherwise false for form data.")
    description: str = Field(description="A brief description of how this endpoint is vulnerable and will be targeted.")

class ExploitPlan(BaseModel):
    """The structured plan created by the Analyst Agent, including detailed endpoint information."""
    vulnerability_type: str = Field(description="The specific type of vulnerability identified (e.g., 'SQL Injection', 'NoSQL Injection', 'IDOR').")
    vulnerable_endpoints: List[VulnerableEndpoint] = Field(description="A list of all identified vulnerable endpoints, their associated service, methods, parameters, and payload type.")
    exploitation_strategy: str = Field(description="A detailed, step-by-step natural language plan for how the exploit script should work. This plan must refer to the specific services and endpoints listed above.")
    example_payload: str = Field(description="A single, clear example payload or URL modification that demonstrates the core of the exploit logic. This should be a raw payload, not part of a command.")

class CoderOutput(BaseModel):
    """The structured output from the Coder Agent."""
    code: str = Field(description="The complete, final Python code for the solve.py script.")

class AgentState(TypedDict):
    source_code: str
    services: List[ServiceInfo]
    flag_format: str
    exploit_plan: Optional[ExploitPlan]
    script_code: Optional[str]
    execution_output: Optional[str]
    log: Annotated[list, operator.add]
    iteration: int

def clean_python_code(code: str) -> str:
    """Removes markdown fences and other common LLM artifacts from code."""
    match = re.search(r"```python\n(.*?)\n```", code, re.DOTALL)
    if match:
        code = match.group(1)
    return code.strip().replace("```python", "").replace("```", "")

def parse_docker_compose(file_path: str) -> List[ServiceInfo]:
    """Parses a docker-compose.yaml file to extract service names and their URLs."""
    if not os.path.exists(file_path):
        return []
    
    services = []
    try:
        with open(file_path, 'r') as f:
            compose_data = yaml.safe_load(f)
        
        if not compose_data or 'services' not in compose_data:
            return []

        for service_name, service_details in compose_data['services'].items():
            if 'ports' in service_details:
                for port_mapping in service_details['ports']:
                    host_port = str(port_mapping).split(':')[0]
                    url = f"http://localhost:{host_port}"
                    services.append(ServiceInfo(name=service_name, url=url))
                    # break 
    except Exception as e:
        print(colored(f"Error parsing docker-compose file: {e}", "red"))
    
    return services


def analyst_node(state: AgentState):
    """Analyzes source code and service info to create a detailed, service-aware exploit plan."""
    print(colored("--- STAGE 1: Analyst Agent ---", "cyan"))
    
    prompt = PromptTemplate.from_template(
        """You are a master cybersecurity analyst. Your sole responsibility is to analyze the provided source code and create a highly detailed and structured exploit plan to find a flag.

        **CONTEXT:**
        The application is composed of the following services. You must determine which service is vulnerable and link your findings to the correct service name.
        - **Available Services:** {services}

        **TASK:**
        1.  **Analyze Source Code:** Meticulously review the application source code below.
        2.  **Identify Vulnerability:** Find the most likely vulnerability. You must classify it as one of the following:
            - **SQL Injection:** User input is insecurely concatenated into a SQL query.
            - **NoSQL Injection:** User input is insecurely used in a NoSQL database query (e.g., MongoDB with `$where` or query operators like `$ne`, `$gt`).
            - **IDOR (Insecure Direct Object Reference):** A user-controlled identifier (like a user ID in a URL path or parameter) is used to access data without an authorization check, allowing you to access data belonging to other users.
        3.  **Detail Vulnerable Endpoints:** For the identified vulnerability, detail the endpoint.
            - The **`service_name`** from the list above.
            - The exact URL **`path`**. For IDOR, this might be a template like `/api/users/{{ID}}`.
            - The required HTTP **`method`**.
            - The specific injectable **`parameters`**. For IDOR, this would be the identifier (e.g., 'id').
            - Whether the payload should be **JSON** (`is_json_payload`).
            - A **`description`** of why it's vulnerable.
        4.  **Handle Credentials & Registration:** If the exploit requires creating a user or logging in, you must use simple, predictable credentials (e.g., `username='user'`, `password='user'`, `email='user@example.com'`). Ensure your strategy accounts for all required registration fields found in the source code. Do not generate random credentials unless necessary.
        5.  **Formulate Strategy:** Create a clear, step-by-step strategy. For IDOR, this usually involves iterating through IDs (e.g., 1, 2, 3...) to find a valid one that reveals a flag.
        6.  **Provide Example Payload:** Give one clear, raw example payload or URL modification.

        **Source Code Bundle:**
        {source_code}
        """
    )
    
    llm = ChatGoogleGenerativeAI(temperature=0, model="gemini-2.5-pro")
    analyst_chain = prompt | llm.with_structured_output(ExploitPlan)
    
    exploit_plan = analyst_chain.invoke({
        "source_code": state["source_code"],
        "services": state["services"]
    })

    print(colored("--- ANALYST OUTPUT ---", "green"))
    print(colored(exploit_plan.model_dump_json(indent=2), "green"))
    
    return {
        "exploit_plan": exploit_plan,
        "log": [f"Analyst identified: {exploit_plan.vulnerability_type}"]
    }

def coder_node(state: AgentState):
    """Receives the exploit plan and writes the complete Python script with a hardcoded URL."""
    print(colored("--- STAGE 2: Coder Agent ---", "cyan"))

    plan = state['exploit_plan']
    target_service_name = plan.vulnerable_endpoints[0].service_name
    target_url = None
    for service in state['services']:
        if service.name == target_service_name:
            target_url = service.url
            break
    
    if not target_url:
        error_msg = f"Coder failed: Could not find URL for target service '{target_service_name}'."
        print(colored(error_msg, "red"))
        return {"execution_output": error_msg, "log": [error_msg]}

    coder_prompt_template_str = ""
    inputs = {}
    
    if state.get('execution_output'):
        print(colored("--- Debugging previous code ---", "magenta"))
        coder_prompt_template_str = """You are a Python debugging expert. Your previous script failed. Rewrite the script to fix the bug.
            **Original Plan:** {exploit_plan}
            **Target URL (Hardcode this):** {target_url}
            **Key instruction:** A common error is mixing up `json=` and `data=` for POST requests. Double-check the `is_json_payload` flag in the plan and ensure the corrected code uses the right one.
            **Previous Broken Code:**\n```python\n{script_code}\n```
            **Execution Error:**\n{execution_output}
            Your task is to provide the corrected, complete Python script. Do not add any extra explanations."""
        inputs = {
            "exploit_plan": state['exploit_plan'].model_dump_json(indent=2),
            "script_code": state['script_code'],
            "execution_output": state['execution_output'],
            "target_url": target_url,
        }
    else:
        coder_prompt_template_str = """You are an expert Python developer specializing in cybersecurity. Your task is to write a complete exploit script based on the provided detailed plan.
            **IMPORTANT:**
            - You **MUST** hardcode the target URL into the script: `{target_url}`
            - You **MUST** use the precise endpoint path, HTTP method, and parameter names from the plan.
            - **Pay close attention to the `is_json_payload` flag** in the plan. Use `json=` for `true`, `data=` for `false`.
            - The script must not take any command-line arguments.
            
            **Detailed Exploit Plan:**\n{exploit_plan}
            
            **Script Requirements:**
            - Must be a standalone Python script named `solve.py`.
            - Must have the URL `{target_url}` hardcoded inside it.
            - Must execute the plan precisely.
            - Make sure to add a print statement after every request made (`print(response.text)`). Do not skip this at all.
            - The flag format is `{flag_format}`.
            
            Write the complete Python script now."""
        inputs = {
            "exploit_plan": state['exploit_plan'].model_dump_json(indent=2),
            "flag_format": state["flag_format"],
            "target_url": target_url,
        }

    coder_prompt_template = PromptTemplate.from_template(coder_prompt_template_str)
    llm = ChatGoogleGenerativeAI(temperature=0, model="gemini-2.5-pro")
    coder_chain = coder_prompt_template | llm.with_structured_output(CoderOutput)

    result = coder_chain.invoke(inputs)
    
    print(colored("--- CODER OUTPUT ---", "green"))
    print(colored(result.model_dump_json(indent=2), "green"))

    return {
        "script_code": result.code,
        "log": [f"Coder generated script for {state['exploit_plan'].vulnerability_type} exploit targeting {target_url}."]
    }

def execution_node(state: AgentState):
    """Writes the code to a file and executes it."""
    print(colored("--- STAGE 3: Execution & Evaluation ---", "cyan"))
    
    script_code = state["script_code"]
    if not script_code:
        error_msg = "Execution failed: No script code was generated."
        print(colored(error_msg, "red"))
        return {"execution_output": error_msg, "log": [error_msg]}

    write_python_script.invoke({
        "filename": "solve.py",
        "code": script_code
    })
    
    output = execute_script.invoke({
        "filename": "solve.py"
    })
    
    flag_format = state["flag_format"]
    if flag_format in output and "traceback" not in output.lower() and "error" not in output.lower():
        feedback = "Success"
        print(colored(f"--- EVALUATION: Success (found indicator '{flag_format}') ---", "green"))
    else:
        feedback = "Failure: The script did not return the expected flag or it produced an error."
        print(colored("--- EVALUATION: Failure/Error Detected ---", "red"))
        
    return {
        "execution_output": output,
        "log": [f"Execution complete. Result: {feedback}"],
        "iteration": state["iteration"] + 1
    }

def final_extraction_node(state: AgentState):
    """Final node to extract and display the flag."""
    print(colored("--- MISSION COMPLETE: Extracting Flag ---", "green"))
    output = state["execution_output"]
    flag_format = state["flag_format"]
    log_message = "Could not automatically extract flag, but success was detected. Check stdout."
    try:
        pattern = rf"{re.escape(flag_format)}\{{[^\}}]+\}}"
        match = re.search(pattern, output)
        if match:
            flag = match.group(0)
            print(colored(f"--- FOUND: {flag} ---", "green", attrs=['bold']))
            log_message = f"Success! Extracted Flag: {flag}"
    except Exception as e:
        log_message = f"Flag indicator found, but regex extraction failed: {e}. Check stdout."

    return {"log": [log_message]}

def should_continue(state: AgentState):
    if "Success" in state["log"][-1]:
        return "extract_flag"
    if state["iteration"] >= 3:
        print(colored("--- GOTO: Max iterations reached. Halting. ---", "red"))
        return END
    return "coder"

def read_source_directory(path: str) -> str:
    """Reads all files in a directory and bundles them into a single string."""
    bundle = ""
    if not os.path.isdir(path): return ""
    for root, _, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, path)
            bundle += f"--- FILE: {relative_path} ---\n\n"
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    bundle += f.read()
                bundle += "\n\n"
            except Exception as e:
                bundle += f"[Error reading file: {e}]\n\n"
    return bundle

def main():
    parser = argparse.ArgumentParser(description="Multi-Agent System for solving CTFs from a source directory.")
    parser.add_argument("--src-dir", default="src", help="Path to the directory containing docker-compose.yaml and the 'application' source code.")
    parser.add_argument("--flag-format", default="ev", help="The expected starting format of the flag (e.g., 'ev', 'flag').")
    args = parser.parse_args()

    compose_path = os.path.join(args.src_dir, 'docker-compose.yaml')
    app_code_path = os.path.join(args.src_dir, 'application')

    services = parse_docker_compose(compose_path)
    if not services:
        print(colored(f"Error: Could not find or parse 'docker-compose.yaml' at '{compose_path}' or no services with ports found.", "red"))
        return
        
    source_bundle = read_source_directory(app_code_path)
    if not source_bundle:
        print(colored(f"Error: Could not read source code from directory '{app_code_path}'. Please check the path.", "red"))
        return

    workflow = StateGraph(AgentState)
    workflow.add_node("analyst", analyst_node)
    workflow.add_node("coder", coder_node)
    workflow.add_node("executor", execution_node)
    workflow.add_node("extract_flag", final_extraction_node)

    workflow.set_entry_point("analyst")
    workflow.add_edge("analyst", "coder")
    workflow.add_edge("coder", "executor")
    workflow.add_conditional_edges("executor", should_continue, {"extract_flag": "extract_flag", "coder": "coder", END: END})
    workflow.add_edge("extract_flag", END)

    app = workflow.compile()

    initial_state = {
        "source_code": source_bundle,
        "services": services,
        "flag_format": args.flag_format,
        "log": [],
        "iteration": 0
    }
    
    final_state = None
    try:
        final_state = app.invoke(initial_state, {"recursion_limit": 15})
    except Exception as e:
        print(colored(f"\nAn error occurred during agent execution: {e}", "red", attrs=['bold']))

    print(colored("\n" + "="*50, "green"))
    print(colored("   AGENT RUN COMPLETE", "green", attrs=['bold']))
    print(colored("="*50, "green"))
    if final_state:
        print("\n--- DISCOVERED SERVICES ---")
        for service in final_state.get('services', []):
            print(colored(f"- Service: {service.name}, URL: {service.url}", 'cyan'))

        print("\n--- FINAL LOG ---")
        for log_entry in final_state.get('log', []):
            print(f"- {log_entry}")
        
        print("\n--- FINAL EXPLOIT PLAN ---")
        if final_state.get('exploit_plan'):
            plan = final_state['exploit_plan']
            print(colored(f"Vulnerability Type: {plan.vulnerability_type}", 'white'))
            if plan.vulnerable_endpoints:
                for endpoint in plan.vulnerable_endpoints:
                    print(colored(f"  Service: {endpoint.service_name}, Path: {endpoint.path}, Method: {endpoint.method}, JSON: {endpoint.is_json_payload}", 'white'))
            print(colored(f"Strategy: {plan.exploitation_strategy}", 'white'))

        print("\n--- FINAL SCRIPT CODE ---")
        print(colored(final_state.get('script_code', 'N/A'), 'white'))

        print("\n--- FINAL EXECUTION OUTPUT ---")
        print(colored(final_state.get('execution_output', 'N/A'), 'yellow'))
        
        if any("Success" in log for log in final_state.get('log', [])):
             print(colored("\nMISSION ACCOMPLISHED!", "white", "on_green", attrs=['bold']))
        else:
             print(colored("\nMISSION FAILED.", "white", "on_red", attrs=['bold']))
    else:
        print(colored("The agent run resulted in an unrecoverable error.", "red"))

if __name__ == "__main__":
    main()
