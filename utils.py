import json
import logging
import os
import subprocess
import tempfile
import contextlib
import importlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Dict, Optional

def find_c_files(directory):
    """
    Find all .c files in the given directory.
    
    Args:
        directory (str): The path to the directory to search.
    
    Returns:
        list: A list of Path objects representing the .c files found.
    """
    dir_path = Path(directory)
    
    if not dir_path.is_dir():
        print(f"Error: {directory} is not a valid directory.")
        return []
    
    c_files = sorted(list(dir_path.glob('**/*.c')))
    
    return c_files

def find_c_files_int(directory, start=None, end=None):
    """
    Find .c files in the given directory, optionally within a specified range.
    
    Args:
    directory (str): The path to the directory to search.
    start (int, optional): The starting number for file selection (inclusive).
    end (int, optional): The ending number for file selection (inclusive).
    
    Returns:
    list: A list of Path objects representing the selected .c files.
    """
    dir_path = Path(directory)
    
    if not dir_path.is_dir():
        print(f"Error: {directory} is not a valid directory.")
        return []
    
    # Find all .c files
    all_c_files = list(dir_path.glob('*.c'))
    
    # Sort files based on their numeric prefix
    sorted_c_files = sorted(all_c_files, key=lambda x: int(x.stem))
    
    # If start and end are specified, filter the list
    if start is not None and end is not None:
        filtered_c_files = [f for f in sorted_c_files if start <= int(f.stem) <= end]
    elif start is not None:
        filtered_c_files = [f for f in sorted_c_files if int(f.stem) >= start]
    elif end is not None:
        filtered_c_files = [f for f in sorted_c_files if int(f.stem) <= end]
    else:
        filtered_c_files = sorted_c_files
    
    return filtered_c_files

def load_lldb_interface():
    # Find the lldb module and load it into LLDB's Python interpreter.
    lldb_executable = "lldb"
    args = [lldb_executable, '-P']
    pythonpath = subprocess.check_output(args, stderr=subprocess.STDOUT).rstrip().decode('utf-8')
    sys.path.append(pythonpath)
    module = importlib.import_module('lldb')
    return module

def run_cmd(cmd: List[str], working_dir: Optional[Path] = None) -> str:
    if working_dir is None:
        working_dir = Path.cwd()
    
    result = subprocess.run(cmd, cwd=str(working_dir), check=True, capture_output=True, text=True)
    return result.stdout.strip()

def get_compiler_version(compiler: str) -> Optional[str]:
    try:
        result = run_cmd([compiler, '--version'])
        return result.split('\n')[0].split()[-1]
    except subprocess.CalledProcessError:
        logging.error(f"Failed to get version for {compiler}")
        return None

def check_installed_compilers() -> Dict[str, str]:
    compilers = {
        'gcc': 'gcc',
        'clang': 'clang',
        'ccomp': 'ccomp'
    }
    
    return {name: version for name, cmd in compilers.items()
            if (version := get_compiler_version(cmd)) is not None}


def save_to_tmp_file(content: str) -> tempfile.NamedTemporaryFile:
    tmp_file = tempfile.NamedTemporaryFile(mode='w+', delete=False)
    tmp_file.write(content)
    tmp_file.flush()
    return tmp_file



import os
import sys
import re
import subprocess
import importlib.util
from typing import List, Optional, Dict, Any, Tuple
import logging
import platform

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
# Create a logger
logger = logging.getLogger(__name__)
class LineNumberExtractor:
    def __init__(self, lldb_path: Optional[str] = None):
        self.IS_MACOS = platform.system() == "Darwin"
        self.lldb = self._load_lldb_interface(lldb_path)
        self.logger = self._setup_logger()

    def _setup_logger(self):
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger

    def _load_lldb_interface(self, lldb_path: Optional[str] = None):
        try:
            if lldb_path:
                spec = importlib.util.spec_from_file_location("lldb", lldb_path)
                lldb = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(lldb)
            else:
                lldb_executable = "lldb"
                args = [lldb_executable, '-P']
                pythonpath = subprocess.check_output(args, stderr=subprocess.STDOUT).rstrip().decode('utf-8')
                sys.path.append(pythonpath)
                lldb = importlib.import_module('lldb')
            return lldb
        except Exception as e:
            self.logger.error(f"Failed to load LLDB interface: {e}")
            raise

    def get_debug_file_path(self, binary_file: str) -> str:
        if self.IS_MACOS:
            return f"{binary_file}.dSYM/Contents/Resources/DWARF/{os.path.basename(binary_file)}"
        return binary_file

    def run_dwarfdump(self, binary_file: str, debug_info: bool = False) -> str:
        debug_file = self.get_debug_file_path(binary_file)
        cmd = ["llvm-dwarfdump"]
        if debug_info:
            cmd.append("--debug-info")
        else:
            cmd.append("--debug-line")
        cmd.append(debug_file)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to run dwarfdump on {debug_file}: {e}")
            raise

    def get_source_files(self, binary_file: str) -> List[str]:
        output = self.run_dwarfdump(binary_file, debug_info=True)
        compile_unit_pattern = re.compile(r'DW_TAG_compile_unit.*?DW_AT_name\s+\("(.+?)"\)', re.DOTALL)
        return [os.path.basename(match.group(1)) for match in compile_unit_pattern.finditer(output)]

    def parse_debug_line(self, output: str) -> Tuple[Dict[int, Dict[str, Any]], List[Dict[str, Any]]]:
        file_table = {}
        line_info = []
        current_file = None
        
        file_table_pattern = re.compile(r'file_names\[\s*(\d+)\]:')
        file_name_pattern = re.compile(r'name: "(.+)"')
        dir_index_pattern = re.compile(r'dir_index: (\d+)')
        line_entry_pattern = re.compile(r'0x([0-9a-f]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)')

        parsing_file_table = False

        for line in output.split('\n'):
            if line.startswith("file_names["):
                parsing_file_table = True
                if match := file_table_pattern.search(line):
                    current_file = int(match.group(1))
                    file_table[current_file] = {}
            elif parsing_file_table:
                if match := file_name_pattern.search(line):
                    file_table[current_file]['name'] = match.group(1)
                elif match := dir_index_pattern.search(line):
                    file_table[current_file]['dir_index'] = int(match.group(1))
                    parsing_file_table = False
            elif line.startswith("Address"):
                parsing_file_table = False
            elif match := line_entry_pattern.search(line):
                address, line_num, column, file_num, isa, discriminator, flags = match.groups()
                line_info.append({
                    'address': int(address, 16),
                    'line': int(line_num),
                    'column': int(column),
                    'file': int(file_num),
                    'isa': int(isa),
                    'discriminator': int(discriminator),
                    'flags': flags.strip()
                })
   
        return file_table, line_info

    def get_line_numbers_by_file(self, file_table: Dict[int, Dict[str, Any]], 
                                 line_info: List[Dict[str, Any]]) -> Dict[str, List[int]]:
        line_numbers_by_file = {}
        for entry in line_info:
            file_name = os.path.basename(file_table.get(entry['file'], {}).get('name', ''))
            if file_name and 'is_stmt' in entry['flags']:
                if file_name not in line_numbers_by_file:
                    line_numbers_by_file[file_name] = set()
                line_numbers_by_file[file_name].add(entry['line'])
        
        return {file: sorted(lines) for file, lines in line_numbers_by_file.items()}

    @contextlib.contextmanager
    def _lldb_session(self, file_path):
        debugger = self.lldb.SBDebugger.Create()
        debugger.SetAsync(False)
        target = None
        process = None

        try:
            target = debugger.CreateTargetWithFileAndArch(file_path, self.lldb.LLDB_ARCH_DEFAULT)
            if not target.IsValid():
                self.logger.error("Target is not valid")
                raise RuntimeError("Invalid target")

            yield target

        finally:
            try:
                if process and process.IsValid():
                    process.Kill()
                    process.Destroy()
                if target and target.IsValid():
                    target.DeleteAllBreakpoints()
                    debugger.DeleteTarget(target)
            except Exception as cleanup_error:
                self.logger.error(f"Error during cleanup: {str(cleanup_error)}")
            self.lldb.SBDebugger.Destroy(debugger)

    def verify_line_nums(self, source_file: str, file_path: str, line_numbers: List[int]) -> Optional[List[int]]:
        with self._lldb_session(file_path) as target:
            verified_line_nums = set()
            breakpoints = []

            for line_number in line_numbers:
                bp = target.BreakpointCreateByLocation(source_file, line_number)
                if bp.IsValid():
                    breakpoints.append((bp, line_number))
                else:
                    self.logger.warning(f"Could not create breakpoint at line {line_number}")

            process = target.LaunchSimple(None, None, os.getcwd())
            if not process.IsValid():
                self.logger.error("Could not launch process")
                return None

            while process.GetState() == self.lldb.eStateStopped:
                thread = process.GetSelectedThread()
                if thread.GetStopReason() == self.lldb.eStopReasonBreakpoint:
                    frame = thread.GetFrameAtIndex(0)
                    line_number_hit = frame.GetLineEntry().GetLine()
                    for bp, line_number in breakpoints:
                        if bp.GetHitCount() > 0 and line_number == line_number_hit:
                            verified_line_nums.add(line_number)
                            break
                process.Continue()

            return sorted(list(verified_line_nums))
    # _cleanup cannot work under ThreadPoolExcutor 
    # def verify_line_nums(self, source_file: str, file_path: str, line_numbers: List[int]) -> Optional[List[int]]:
    #     debugger = self.lldb.SBDebugger.Create()
    #     debugger.SetAsync(False)
        
    #     try:
    #         target = debugger.CreateTargetWithFileAndArch(file_path, self.lldb.LLDB_ARCH_DEFAULT)
    #         if not target.IsValid():
    #             self.logger.error("Target is not valid")
    #             return None

    #         verified_line_nums = set()
    #         breakpoints = []

    #         for line_number in line_numbers:
    #             bp = target.BreakpointCreateByLocation(source_file, line_number)
    #             if bp.IsValid():
    #                 breakpoints.append((bp, line_number))
    #             else:
    #                 self.logger.warning(f"Could not create breakpoint at line {line_number}")

    #         process = target.LaunchSimple(None, None, os.getcwd())
    #         if not process.IsValid():
    #             self.logger.error("Could not launch process")
    #             return None

    #         while process.GetState() == self.lldb.eStateStopped:
    #             thread = process.GetSelectedThread()
    #             if thread.GetStopReason() == self.lldb.eStopReasonBreakpoint:
    #                 frame = thread.GetFrameAtIndex(0)
    #                 line_number_hit = frame.GetLineEntry().GetLine()
    #                 for bp, line_number in breakpoints:
    #                     if bp.GetHitCount() > 0 and line_number == line_number_hit:
    #                         verified_line_nums.add(line_number)
    #                         break
    #             process.Continue()

    #         return sorted(list(verified_line_nums))

    #     except Exception as e:
    #         self.logger.error(f"Error in verify_line_nums: {str(e)}")
    #         return None
    #     finally:
    #         self._cleanup(debugger, target, process)

    # def _cleanup(self, debugger, target, process):
    #     try:
    #         if 'process' in locals() and process.IsValid():
    #             process.Kill()
    #             process.Destroy()
    #         if 'target' in locals() and target.IsValid():
    #             target.DeleteAllBreakpoints()
    #             debugger.DeleteTarget(target)
    #     except Exception as cleanup_error:
    #         self.logger.error(f"Error during cleanup: {str(cleanup_error)}")
    #     self.lldb.SBDebugger.Destroy(debugger)

    def get_line_nums(self, binary_file: str) -> Dict[str, List[int]]:
        try:
            source_files = self.get_source_files(binary_file)
            dwarfdump_output = self.run_dwarfdump(binary_file)
            file_table, line_info = self.parse_debug_line(dwarfdump_output)
            line_numbers_by_file = self.get_line_numbers_by_file(file_table, line_info)
            
            verified_line_numbers = {}
            for source_file, line_numbers in line_numbers_by_file.items():
                if source_file in source_files:  # Only verify for compile units
                    verified_lines = self.verify_line_nums(source_file, binary_file, line_numbers)
                    if verified_lines:
                        verified_line_numbers[source_file] = verified_lines
            
            return verified_line_numbers
        except Exception as e:
            self.logger.error(f"Error in get_line_nums: {str(e)}")
            return {}

# Example usage
if __name__ == "__main__":
    extractor = LineNumberExtractor()
    
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary_file1> [<binary_file2> ...]")
        sys.exit(1)

    for binary_file in sys.argv[1:]:
        line_nums_by_file = extractor.get_line_nums(binary_file)
        if line_nums_by_file:
            print(f"Results for {binary_file}:")
            for source_file, line_nums in line_nums_by_file.items():
                print(f"  Source file: {source_file}")
                print(f"  Line numbers: {line_nums}")
        else:
            print(f"Failed to get line numbers for {binary_file}")

# if __name__ == "__main__":
#     logging.basicConfig(level=logging.DEBUG)
#     config = import_config()
#     logging
