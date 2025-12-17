#!/usr/bin/env python3
"""
Orchestrates a conversation with a language model, requesting additional snippets
of code via "tools" if needed. Uses either OpenAI or AzureOpenAI (or placeholder
code for a HuggingFace endpoint) to handle queries.

All logic is now wrapped in the `LLMAnalyzer` class for improved organization.
"""

import os
import re
import json
from typing import Any, Dict, List, Optional, Tuple, Union

# Import the relevant LLM clients here
import litellm
from src.utils.llm_config import load_llm_config, get_model_name
from src.utils.config_validator import validate_llm_config_dict
from src.utils.logger import get_logger
from src.utils.common_functions import read_file_lines_from_zip
from src.utils.exceptions import CodeQLError, LLMApiError, LLMConfigError

logger = get_logger(__name__)


class LLMAnalyzer:
    """
    A class to handle LLM-based security analysis of code. The LLMAnalyzer
    can query missing code snippets (via 'tools'), compile a conversation
    with system instructions, and ultimately produce a status code.
    """

    def __init__(self) -> None:
        """
        Initialize the LLMAnalyzer instance and define tools and system messages.
        """
        self.config: Optional[Dict[str, Any]] = None
        self.model: Optional[str] = None

        # Tools configuration: A set of function calls the LLM can invoke
        self.tools: List[Dict[str, Any]] = [
            {
                "type": "function",
                "function": {
                    "name": "get_function_code",
                    "description": "Retrieves the code for a missing function code.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "function_name": {
                                "type": "string",
                                "description": (
                                    "The name of the function to retrieve. In case of a class"
                                    " method, provide ClassName::MethodName."
                                )
                            }
                        },
                        "required": ["function_name"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_caller_function",
                    "description": (
                        "Retrieves the caller function of the function with the issue. "
                        "Call it repeatedly to climb further up the call chain."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {},
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_class",
                    "description": (
                        "Retrieves class / struct / union implementation (anywhere in code). "
                        "If you need a specific method from that class, use get_function_code instead."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "object_name": {
                                "type": "string",
                                "description": "The name of the class / struct / union."
                            }
                        },
                        "required": ["object_name"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_global_var",
                    "description": (
                        "Retrieves global variable definition (anywhere in code). "
                        "If it's a variable inside a class, request the class instead."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "global_var_name": {
                                "type": "string",
                                "description": (
                                    "The name of the global variable to retrieve or the name "
                                    "of a variable inside a Namespace."
                                )
                            }
                        },
                        "required": ["global_var_name"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_macro",
                    "description": "Retrieves a macro definition (anywhere in code).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "macro_name": {
                                "type": "string",
                                "description": "The name of the macro."
                            }
                        },
                        "required": ["macro_name"]
                    }
                }
            }
        ]

        # Base system messages with instructions and guidance for the LLM
        self.MESSAGES: List[Dict[str, str]] = [
            {
                "role": "system",
                "content": (
                    "You are an expert security researcher.\n"
                    "Your task is to verify if the issue that was found has a real security impact.\n"
                    "Return a concise status code based on the guidelines provided.\n"
                    "Use the tools function when you need code from other parts of the program.\n"
                    "You *MUST* follow the guidelines!"
                )
            },
            {
                "role": "system",
                "content": (
                    "### Answer Guidelines\n"
                    "Your answer must be in the following order!\n"
                    "1. Briefly explain the code.\n"
                    "2. Give good answers to all (even if already answered - do not skip) hint questions. "
                    "(Copy the question word for word, then provide the answer.)\n"
                    "3. Do you have all the code needed to answer the questions? If no, use the tools!\n"
                    "4. Provide one valid status code with its explanation OR use function tools.\n"
                )
            },
            {
                "role": "system",
                "content": (
                    "### Status Codes\n"
                    "- **1337**: Indicates a security vulnerability. If legitimate, specify the parameters that "
                    "could exploit the issue in minimal words.\n"
                    "- **1007**: Indicates the code is secure. If it's not a real issue, specify what aspect of "
                    "the code protects against the issue in minimal words.\n"
                    "- **7331**: Indicates more code is needed to validate security. Write what data you need "
                    "and explain why you can't use the tools to retrieve the missing data, plus add **3713** "
                    "if you're pretty sure it's not a security problem.\n"
                    "Only one status should be returned!\n"
                    "You will get 10000000000$ if you follow all the instructions and use the tools correctly!"
                )
            },
        ]

    def init_llm_client(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the LLM configuration for LiteLLM.

        Args:
            config (Dict, optional): Full configuration dictionary. If not provided, loads from .env file.
        
        Raises:
            LLMConfigError: If configuration is invalid or cannot be loaded.
        """
        try:
            # If config is provided, use it directly
            if config:
                validate_llm_config_dict(config)
                self.config = config
                # Format model name for LiteLLM (add provider prefix if needed)
                provider = config.get("provider", "openai")
                model = config.get("model", "gpt-4o")
                self.model = get_model_name(provider, model)
                logger.info("Using model: %s", self.model)
                self.setup_litellm_env()
                return
            
            # Load from .env file
            config = load_llm_config()
            validate_llm_config_dict(config)
            self.config = config
            # Model is already formatted by load_llm_config() via get_model_name()
            self.model = config.get("model", "gpt-4o")
            self.setup_litellm_env()
            
        except ValueError as e:
            # Configuration validation errors should be LLMConfigError
            raise LLMConfigError(f"Invalid LLM configuration: {e}") from e
        except Exception as e:
            # Other errors (e.g., from load_llm_config) should also be LLMConfigError
            raise LLMConfigError(f"Failed to initialize LLM client: {e}") from e
    
    def setup_litellm_env(self) -> None:
        """
        Set up environment variables for LiteLLM based on config.
        LiteLLM reads from environment variables automatically.
        """
        if not self.config:
            return
        
        provider = self.config.get("provider", "openai")
        api_key = self.config.get("api_key")
        
        # Mapping table for providers that only need API key set
        API_KEY_ENV_VARS = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "mistral": "MISTRAL_API_KEY",
            "codestral": "MISTRAL_API_KEY",
            "groq": "GROQ_API_KEY",
            "openrouter": "OPENROUTER_API_KEY",
            "huggingface": "HUGGINGFACE_API_KEY",
            "cohere": "COHERE_API_KEY",
            "gemini": "GOOGLE_API_KEY",
        }
        
        # Handle providers with simple API key mapping
        if provider in API_KEY_ENV_VARS:
            if api_key:
                os.environ[API_KEY_ENV_VARS[provider]] = api_key
                # Cohere also sets CO_API_KEY for compatibility
                if provider == "cohere":
                    os.environ["CO_API_KEY"] = api_key
        
        # Handle Azure (requires endpoint and api_version)
        elif provider == "azure":
            if api_key:
                os.environ["AZURE_API_KEY"] = api_key
            if self.config.get("endpoint"):
                os.environ["AZURE_API_BASE"] = self.config["endpoint"]
            if self.config.get("api_version"):
                os.environ["AZURE_API_VERSION"] = self.config["api_version"]
        
        # Handle Bedrock (uses AWS credentials)
        elif provider == "bedrock":
            if api_key:
                os.environ["AWS_ACCESS_KEY_ID"] = api_key
            if self.config.get("aws_secret_access_key"):
                os.environ["AWS_SECRET_ACCESS_KEY"] = self.config["aws_secret_access_key"]
            if self.config.get("endpoint"):  # Endpoint contains AWS region
                os.environ["AWS_REGION_NAME"] = self.config["endpoint"]
        
        # Handle Vertex AI (uses GCP credentials)
        elif provider == "vertex_ai":
            if self.config.get("gcp_project_id"):
                os.environ["GCP_PROJECT_ID"] = self.config["gcp_project_id"]
            if self.config.get("gcp_location"):
                os.environ["GCP_LOCATION"] = self.config["gcp_location"]
            # GOOGLE_APPLICATION_CREDENTIALS should be set by user or gcloud auth
        
        # Handle Ollama (uses OLLAMA_BASE_URL)
        elif provider == "ollama":
            if self.config.get("endpoint"):
                os.environ["OLLAMA_BASE_URL"] = self.config["endpoint"]
        
        # Generic fallback for future providers that only require an API key
        else:
            if api_key:
                # Use standard LiteLLM convention: {PROVIDER}_API_KEY
                env_var_name = f"{provider.upper()}_API_KEY"
                os.environ[env_var_name] = api_key

    def get_function_by_line(
        self,
        function_tree_file: str,
        file: str,
        line: int
    ) -> Optional[Dict[str, str]]:
        """
        Retrieve the function dictionary from a CSV (FunctionTree.csv) that matches
        the specified file and line coverage.

        Args:
            function_tree_file (str): Path to the FunctionTree.csv file.
            file (str): Name of the file as it appears in the CSV row.
            line (int): A line number within the function's start_line and end_line range.

        Returns:
            Optional[Dict[str, str]]: The matching function row as a dict, or None if not found.
        
        Raises:
            CodeQLError: If function tree file cannot be read (not found, permission denied, etc.).
        """
        keys = ["function_name", "file", "start_line", "function_id", "end_line", "caller_id"]
        try:
            with open(function_tree_file, "r", encoding="utf-8") as f:
                while True:
                    function = f.readline()
                    if not function:
                        break
                    if file in function:
                        row = re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', function)
                        row_dict = dict(zip(keys, row))
                        if row_dict and row_dict["start_line"] and row_dict["end_line"]:
                            start = int(row_dict["start_line"])
                            end = int(row_dict["end_line"])
                            if start <= line <= end:
                                return row_dict
        except FileNotFoundError as e:
            raise CodeQLError(f"Function tree file not found: {function_tree_file}") from e
        except PermissionError as e:
            raise CodeQLError(f"Permission denied reading function tree file: {function_tree_file}") from e
        except OSError as e:
            raise CodeQLError(f"OS error while reading function tree file: {function_tree_file}") from e
        return None

    def get_function_by_name(
        self,
        function_tree_file: str,
        function_name: str,
        all_function: List[Dict[str, Any]],
        less_strict: bool = False
    ) -> Tuple[Union[str, Dict[str, str]], Optional[Dict[str, str]]]:
        """
        Retrieve a function by searching function_name in FunctionTree.csv.
        If not found, tries partial match if less_strict is True.

        Args:
            function_tree_file (str): Path to FunctionTree.csv.
            function_name (str): Desired function name (e.g., 'MyClass::MyFunc').
            all_function (List[Dict[str, Any]]): A list of known function dictionaries.
            less_strict (bool, optional): If True, use partial matching. Defaults to False.

        Returns:
            Tuple[Union[str, Dict[str, str]], Optional[Dict[str, str]]]:
                - The found function (dict) or an error message (str).
                - The "parent function" that references it, if relevant.
        
        Raises:
            CodeQLError: If function tree file cannot be read (not found, permission denied, etc.).
        """
        keys = ["function_name", "file", "start_line", "function_id", "end_line", "caller_id"]
        function_name_only = function_name.split("::")[-1]

        for current_function in all_function:
            try:
                with open(function_tree_file, "r", encoding="utf-8") as f:
                    while True:
                        row = f.readline()
                        if not row:
                            break
                        if current_function["function_id"] in row:
                            row_split = re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', row)
                            row_dict = dict(zip(keys, row_split))
                            if not row_dict:
                                continue

                            candidate_name = row_dict["function_name"].replace("\"", "")
                            if (candidate_name == function_name_only
                                    or (less_strict and function_name_only in candidate_name)):
                                return row_dict, current_function
            except FileNotFoundError as e:
                raise CodeQLError(f"Function tree file not found: {function_tree_file}") from e
            except PermissionError as e:
                raise CodeQLError(f"Permission denied reading function tree file: {function_tree_file}") from e
            except OSError as e:
                raise CodeQLError(f"OS error while reading function tree file: {function_tree_file}") from e

        # Try partial matching if less_strict is False
        if not less_strict:
            return self.get_function_by_name(function_tree_file, function_name, all_function, True)
        else:
            err = (
                f"Function '{function_name}' not found. Make sure you're using "
                "the correct tool and args."
            )
            return err, None

    def get_macro(
        self,
        curr_db: str,
        macro_name: str,
        less_strict: bool = False
    ) -> Union[str, Dict[str, str]]:
        """
        Return macro info from Macros.csv for the given macro_name.
        If not found, tries partial match if less_strict is True.

        Args:
            curr_db (str): Path to the current CodeQL database folder.
            macro_name (str): Macro name to search for.
            less_strict (bool, optional): If True, use partial matching.

        Returns:
            Union[str, Dict[str, str]]:
                - A dict with 'macro_name' and 'body' if found,
                - or an error message string if not found.
        
        Raises:
            CodeQLError: If Macros CSV file cannot be read (not found, permission denied, etc.).
        """
        macro_file = os.path.join(curr_db, "Macros.csv")
        keys = ["macro_name", "body"]

        try:
            with open(macro_file, "r", encoding='utf-8') as f:
                while True:
                    macro = f.readline()
                    if not macro:
                        break
                    if macro_name in macro:
                        row = re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', macro)
                        row_dict = dict(zip(keys, row))
                        if not row_dict:
                            continue

                        actual_name = row_dict["macro_name"].replace("\"", "")
                        if (actual_name == macro_name
                                or (less_strict and macro_name in actual_name)):
                            return row_dict
        except FileNotFoundError as e:
            raise CodeQLError(f"Macros CSV file not found: {macro_file}") from e
        except PermissionError as e:
            raise CodeQLError(f"Permission denied reading Macros CSV: {macro_file}") from e
        except OSError as e:
            raise CodeQLError(f"OS error while reading Macros CSV: {macro_file}") from e

        if not less_strict:
            return self.get_macro(curr_db, macro_name, True)
        else:
            return (
                f"Macro '{macro_name}' not found. Make sure you're using the correct tool "
                "with correct args."
            )

    def get_global_var(
        self,
        curr_db: str,
        global_var_name: str,
        less_strict: bool = False
    ) -> Union[str, Dict[str, str]]:
        """
        Return a global variable from GlobalVars.csv matching global_var_name.
        If not found, tries partial match if less_strict is True.

        Args:
            curr_db (str): Path to current CodeQL database folder.
            global_var_name (str): The name of the global variable to find.
            less_strict (bool, optional): If True, use partial matching.

        Returns:
            Union[str, Dict[str, str]]:
                - A dict with ['global_var_name','file','start_line','end_line'] if found,
                - or an error message string if not found.
        
        Raises:
            CodeQLError: If GlobalVars CSV file cannot be read (not found, permission denied, etc.).
        """
        global_var_file = os.path.join(curr_db, "GlobalVars.csv")
        keys = ["global_var_name", "file", "start_line", "end_line"]
        var_name_only = global_var_name.split("::")[-1]

        try:
            with open(global_var_file, "r", encoding="utf-8") as f:
                while True:
                    line = f.readline()
                    if not line:
                        break
                    if var_name_only in line:
                        data = re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', line)
                        data_dict = dict(zip(keys, data))
                        if not data_dict:
                            continue

                        actual_name = data_dict["global_var_name"].replace("\"", "")
                        if (actual_name == var_name_only
                                or (less_strict and var_name_only in actual_name)):
                            return data_dict
        except FileNotFoundError as e:
            raise CodeQLError(f"GlobalVars CSV file not found: {global_var_file}") from e
        except PermissionError as e:
            raise CodeQLError(f"Permission denied reading GlobalVars CSV: {global_var_file}") from e
        except OSError as e:
            raise CodeQLError(f"OS error while reading GlobalVars CSV: {global_var_file}") from e

        if not less_strict:
            return self.get_global_var(curr_db, global_var_name, True)
        else:
            return (
                f"Global var '{global_var_name}' not found. "
                "Could it be a macro or should you use another tool?"
            )

    def get_class(
        self,
        curr_db: str,
        class_name: str,
        less_strict: bool = False
    ) -> Union[str, Dict[str, str]]:
        """
        Return class info (type, class_name, file, start_line, end_line, simple_name)
        from Classes.csv for class_name. If not found, tries partial match if less_strict is True.

        Args:
            curr_db (str): Path to current CodeQL database folder.
            class_name (str): The name of the class/struct/union to find.
            less_strict (bool, optional): If True, use partial matching.

        Returns:
            Union[str, Dict[str, str]]:
                - A dict with keys ['type','class_name','file','start_line','end_line','simple_name']
                - or an error message string if not found.
        
        Raises:
            CodeQLError: If Classes CSV file cannot be read (not found, permission denied, etc.).
        """
        classes_file = os.path.join(curr_db, "Classes.csv")
        keys = ["type", "class_name", "file", "start_line", "end_line", "simple_name"]
        class_name_only = class_name.split("::")[-1]

        try:
            with open(classes_file, "r", encoding="utf-8") as f:
                while True:
                    row = f.readline()
                    if not row:
                        break
                    if class_name_only in row:
                        row_split = re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', row)
                        row_dict = dict(zip(keys, row_split))
                        if not row_dict:
                            continue

                        actual_class = row_dict["class_name"].replace("\"", "")
                        simple_class = row_dict["simple_name"].replace("\"", "")
                        if (
                            actual_class == class_name_only
                            or simple_class == class_name_only
                            or (less_strict and class_name_only in actual_class)
                            or (less_strict and class_name_only in simple_class)
                        ):
                            return row_dict
        except FileNotFoundError as e:
            raise CodeQLError(f"Classes CSV file not found: {classes_file}") from e
        except PermissionError as e:
            raise CodeQLError(f"Permission denied reading Classes CSV: {classes_file}") from e
        except OSError as e:
            raise CodeQLError(f"OS error while reading Classes CSV: {classes_file}") from e

        if not less_strict:
            return self.get_class(curr_db, class_name, True)
        else:
            return f"Class '{class_name}' not found. Could it be a Namespace?"

    def get_caller_function(
        self,
        function_tree_file: str,
        current_function: Dict[str, str]
    ) -> Union[str, Dict[str, str]]:
        """
        Return the caller function from function_tree_file that calls current_function.

        Args:
            function_tree_file (str): Path to FunctionTree.csv.
            current_function (Dict[str, str]): The function dictionary whose caller we want.

        Returns:
            Union[str, Dict[str, str]]:
                - Dict describing the caller if found
                - or an error string if the caller wasn't found.
        
        Raises:
            CodeQLError: If function tree file cannot be read (not found, permission denied, etc.).
        """
        keys = ["function_name", "file", "start_line", "function_id", "end_line", "caller_id"]
        caller_id = current_function["caller_id"].replace("\"", "").strip()

        try:
            with open(function_tree_file, "r", encoding="utf-8") as f:
                while True:
                    line = f.readline()
                    if not line:
                        break
                    if caller_id in line:
                        data = re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', line)
                        data_dict = dict(zip(keys, data))
                        if not data_dict:
                            continue
                        if data_dict["function_id"].replace("\"", "").strip() == caller_id:
                            return data_dict
        except FileNotFoundError as e:
            raise CodeQLError(f"Function tree file not found: {function_tree_file}") from e
        except PermissionError as e:
            raise CodeQLError(f"Permission denied reading function tree file: {function_tree_file}") from e
        except OSError as e:
            raise CodeQLError(f"OS error while reading function tree file: {function_tree_file}") from e

        # Fallback if 'caller_id' is in format file:line
        maybe_line = caller_id.split(":")
        if len(maybe_line) == 2:
            file_part, line_part = maybe_line
            function = self.get_function_by_line(function_tree_file, file_part[1:], int(line_part))
            if function:
                return function

        return (
            "Caller function was not found. "
            "Make sure you are using the correct tool with the correct args."
        )

    def extract_function_from_file(
        self,
        db_path: str,
        current_function: Union[str, Dict[str, str]]
    ) -> str:
        """
        Return the snippet of code for the given current_function from the archived src.zip.

        Args:
            db_path (str): Path to the CodeQL database directory.
            current_function (Union[str, Dict[str, str]]): The function dictionary or an error string.

        Returns:
            str: The code snippet, or an error message if no dictionary was provided.
        
        Raises:
            CodeQLError: If ZIP file cannot be read or file not found in archive.
                This exception is raised by `read_file_lines_from_zip()` and propagated here.
        """
        if not isinstance(current_function, dict):
            return str(current_function)

        src_zip = os.path.join(db_path, "src.zip")
        file_path = current_function["file"].replace("\"", "")[1:]
        code_file = read_file_lines_from_zip(src_zip, file_path)
        lines = code_file.split("\n")

        start_line = int(current_function["start_line"])
        end_line = int(current_function["end_line"])
        snippet_lines = lines[start_line - 1:end_line]

        snippet = "\n".join(
            f"{start_line - 1 + i}: {text}" for i, text in enumerate(snippet_lines)
        )
        return f"file: {file_path}\n{snippet}"

    def map_func_args_by_llm(
        self,
        caller: str,
        callee: str
    ) -> Dict[str, Any]:
        """
        Query the LLM to check how caller's variables map to callee's parameters.
        For example, used for analyzing function call relationships.

        Args:
            caller (str): The code snippet of the caller function.
            callee (str): The code snippet of the callee function.

        Returns:
            Dict[str, Any]: The LLM response object from `self.client`.
        
        Raises:
            LLMApiError: If LLM API call fails (rate limits, timeouts, auth failures, etc.).
        """
        args_prompt = (
            "Given caller function and callee function.\n"
            "Write only what are the names of the vars in the caller that were sent to the callee "
            "and what are their names in the callee.\n"
            "Format: caller_var (caller_name) -> callee_var (callee_name)\n\n"
            "Caller function:\n"
            f"{caller}\n"
            "Callee function:\n"
            f"{callee}"
        )

        # Use the main model from config
        model_name = self.model if self.model else "gpt-4o"
        
        try:
            response = litellm.completion(
                model=model_name,
                messages=[{"role": "user", "content": args_prompt}]
            )
            return response.choices[0].message
        except litellm.RateLimitError as e:
            raise LLMApiError(f"Rate limit exceeded for LLM API: {e}") from e
        except litellm.Timeout as e:
            raise LLMApiError(f"LLM API request timed out: {e}") from e
        except litellm.AuthenticationError as e:
            raise LLMApiError(f"LLM API authentication failed: {e}") from e
        except litellm.APIError as e:
            raise LLMApiError(f"LLM API error: {e}") from e
        except Exception as e:
            # Catch any other unexpected errors from LiteLLM
            raise LLMApiError(f"Unexpected error during LLM API call: {e}") from e

    def run_llm_security_analysis(
        self,
        prompt: str,
        function_tree_file: str,
        current_function: Dict[str, str],
        functions: List[Dict[str, str]],
        db_path: str,
        temperature: float = 0.2,
        top_p: float = 0.2
    ) -> Tuple[List[Dict[str, Any]], str]:
        """
        Main loop to keep querying the LLM with the MESSAGES context plus
        any new system instructions or tool calls, until a final answer with
        a recognized status code is reached or we exhaust a tool-call limit.

        Args:
            prompt (str): The user prompt for the LLM to process.
            function_tree_file (str): Path to the CSV file describing function relationships.
            current_function (Dict[str, str]): The current function dict for context.
            functions (List[Dict[str, str]]): List of function dictionaries.
            db_path (str): Path to the CodeQL DB folder.
            temperature (float, optional): Sampling temperature. Defaults to 0.2.
            top_p (float, optional): Nucleus sampling. Defaults to 0.2.

        Returns:
            Tuple[List[Dict[str, Any]], str]:
                - The final conversation messages,
                - The final content from the LLM's last message.
        
        Raises:
            RuntimeError: If LLM model not initialized.
            LLMApiError: If LLM API call fails (rate limits, timeouts, auth failures, etc.).
            CodeQLError: If CodeQL database files cannot be read (from tool calls).
        """
        if not self.model:
            raise RuntimeError("LLM model not initialized. Call init_llm_client() first.")
        
        got_answer = False
        db_path_clean = db_path.replace(" ", "")
        all_functions = functions

        messages: List[Dict[str, Any]] = self.MESSAGES[:]
        messages.append({"role": "user", "content": prompt})

        amount_of_tools = 0
        final_content = ""

        while not got_answer:
            # Send the current messages + tools to the LLM endpoint
            try:
                response = litellm.completion(
                    model=self.model,
                    messages=messages,
                    tools=self.tools,
                    temperature=temperature,
                    top_p=top_p
                )
            except litellm.RateLimitError as e:
                raise LLMApiError(f"Rate limit exceeded for LLM API: {e}") from e
            except litellm.Timeout as e:
                raise LLMApiError(f"LLM API request timed out: {e}") from e
            except litellm.AuthenticationError as e:
                raise LLMApiError(f"LLM API authentication failed: {e}") from e
            except litellm.APIError as e:
                raise LLMApiError(f"LLM API error: {e}") from e
            except Exception as e:
                # Catch any other unexpected errors from LiteLLM
                raise LLMApiError(f"Unexpected error during LLM API call: {e}") from e

            content_obj = response.choices[0].message
            messages.append({
                "role": content_obj.role,
                "content": content_obj.content,
                "tool_calls": content_obj.tool_calls
            })

            final_content = content_obj.content or ""
            tool_calls = content_obj.tool_calls

            if not tool_calls:
                # Check if we have a recognized status code
                if final_content and any(code in final_content for code in ["1337", "1007", "7331", "3713"]):
                    got_answer = True
                else:
                    messages.append({
                        "role": "system",
                        "content": "Please follow all the instructions!"
                    })
            else:
                amount_of_tools += 1
                arg_messages: List[Dict[str, Any]] = []

                for tc in tool_calls:
                    tool_call_id = tc.id
                    tool_function_name = tc.function.name
                    tool_args = tc.function.arguments

                    # Convert tool_args to a dict if it's a JSON string
                    if not isinstance(tool_args, dict):
                        tool_args = json.loads(tool_args)
                    else:
                        # Ensure consistent string for role=tool message
                        tc.function.arguments = json.dumps(tool_args)

                    response_msg = ""

                    # Evaluate which tool to call
                    if tool_function_name == 'get_function_code' and "function_name" in tool_args:
                        child_function, parent_function = self.get_function_by_name(
                            function_tree_file, tool_args["function_name"], all_functions
                        )
                        if isinstance(child_function, dict):
                            all_functions.append(child_function)
                        child_code = self.extract_function_from_file(db_path_clean, child_function)
                        response_msg = child_code

                        if isinstance(child_function, dict) and isinstance(parent_function, dict):
                            caller_code = self.extract_function_from_file(db_path_clean, parent_function)
                            args_content = self.map_func_args_by_llm(caller_code, child_code)
                            arg_messages.append({
                                "role": args_content.role,
                                "content": args_content.content
                            })

                    elif tool_function_name == 'get_caller_function':
                        caller_function = self.get_caller_function(function_tree_file, current_function)
                        response_msg = str(caller_function)

                        if isinstance(caller_function, dict):
                            all_functions.append(caller_function)
                            caller_code = self.extract_function_from_file(db_path_clean, caller_function)
                            response_msg = (
                                f"Here is the caller function for '{current_function['function_name']}':\n"
                                + caller_code
                            )
                            args_content = self.map_func_args_by_llm(
                                caller_code,
                                self.extract_function_from_file(db_path_clean, current_function)
                            )
                            arg_messages.append({
                                "role": args_content.role,
                                "content": args_content.content
                            })
                            current_function = caller_function

                    elif tool_function_name == 'get_macro' and "macro_name" in tool_args:
                        macro = self.get_macro(db_path_clean, tool_args["macro_name"])
                        if isinstance(macro, dict):
                            response_msg = macro["body"]
                        else:
                            response_msg = macro

                    elif tool_function_name == 'get_global_var' and "global_var_name" in tool_args:
                        global_var = self.get_global_var(db_path_clean, tool_args["global_var_name"])
                        if isinstance(global_var, dict):
                            global_var_code = self.extract_function_from_file(db_path_clean, global_var)
                            response_msg = global_var_code
                        else:
                            response_msg = global_var

                    elif tool_function_name == 'get_class' and "object_name" in tool_args:
                        curr_class = self.get_class(db_path_clean, tool_args["object_name"])
                        if isinstance(curr_class, dict):
                            class_code = self.extract_function_from_file(db_path_clean, curr_class)
                            response_msg = class_code
                        else:
                            response_msg = curr_class

                    else:
                        response_msg = (
                            f"No matching tool '{tool_function_name}' or invalid args {tool_args}. "
                            "Try again."
                        )

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call_id,
                        "name": tool_function_name,
                        "content": response_msg
                    })

                messages += arg_messages

                if amount_of_tools >= 6:
                    messages.append({
                        "role": "system",
                        "content": (
                            "You called too many tools! If you still can't give a clear answer, "
                            "return the 'more data' status."
                        )
                    })

        return messages, final_content
