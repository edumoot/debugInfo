import os
import sys
import re
import subprocess
import importlib.util
from typing import List, Optional, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import platform

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

IS_MACOS = platform.system() == "Darwin"

class LLDBInterface:
    @staticmethod
    def load():
        try:
            lldb_executable = "lldb"
            args = [lldb_executable, '-P']
            pythonpath = subprocess.check_output(args, stderr=subprocess.STDOUT).rstrip().decode('utf-8')
            sys.path.append(pythonpath)
            return importlib.import_module('lldb')
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to load LLDB interface: {e}")
            raise

class DwarfDumpParser:
    @staticmethod
    def get_debug_file_path(binary_file: str) -> str:
        if IS_MACOS:
            return f"{binary_file}.dSYM/Contents/Resources/DWARF/{os.path.basename(binary_file)}"
        return binary_file

    @staticmethod
    def run_dwarfdump(binary_file: str, debug_info: bool = False) -> str:
        debug_file = DwarfDumpParser.get_debug_file_path(binary_file)
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
            logging.error(f"Failed to run dwarfdump on {debug_file}: {e}")
            raise

    @staticmethod
    def get_source_files(binary_file: str) -> List[str]:
        output = DwarfDumpParser.run_dwarfdump(binary_file, debug_info=True)
        compile_unit_pattern = re.compile(r'DW_TAG_compile_unit.*?DW_AT_name\s+\("(.+?)"\)', re.DOTALL)
        return [os.path.basename(match.group(1)) for match in compile_unit_pattern.finditer(output)]

    @staticmethod
    def parse_debug_line(output: str) -> Tuple[Dict[int, Dict[str, Any]], List[Dict[str, Any]]]:
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

    @staticmethod
    def get_line_numbers_by_file(file_table: Dict[int, Dict[str, Any]], 
                                 line_info: List[Dict[str, Any]]) -> Dict[str, List[int]]:
        line_numbers_by_file = {}
        for entry in line_info:
            file_name = os.path.basename(file_table.get(entry['file'], {}).get('name', ''))
            if file_name and 'is_stmt' in entry['flags']:
                if file_name not in line_numbers_by_file:
                    line_numbers_by_file[file_name] = set()
                line_numbers_by_file[file_name].add(entry['line'])
        
        return {file: sorted(lines) for file, lines in line_numbers_by_file.items()}

class LineNumberVerifier:
    def __init__(self, lldb):
        self.lldb = lldb

    def verify_line_nums(self, source_file: str, file_path: str, line_numbers: List[int]) -> Optional[List[int]]:
        debugger = self.lldb.SBDebugger.Create()
        debugger.SetAsync(False)
        
        try:
            target = debugger.CreateTargetWithFileAndArch(file_path, self.lldb.LLDB_ARCH_DEFAULT)
            if not target.IsValid():
                logging.error("Target is not valid")
                return None

            verified_line_nums = set()
            breakpoints = []

            for line_number in line_numbers:
                bp = target.BreakpointCreateByLocation(source_file, line_number)
                if bp.IsValid():
                    breakpoints.append((bp, line_number))
                else:
                    logging.warning(f"Could not create breakpoint at line {line_number}")

            process = target.LaunchSimple(None, None, os.getcwd())
            if not process.IsValid():
                logging.error("Could not launch process")
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

        except Exception as e:
            logging.error(f"Error in verify_line_nums: {str(e)}")
            return None
        finally:
            self._cleanup(debugger, target, process)

    def _cleanup(self, debugger, target, process):
        try:
            if 'process' in locals() and process.IsValid():
                process.Kill()
                process.Destroy()
            if 'target' in locals() and target.IsValid():
                target.DeleteAllBreakpoints()
                debugger.DeleteTarget(target)
        except Exception as cleanup_error:
            logging.error(f"Error during cleanup: {str(cleanup_error)}")
        self.lldb.SBDebugger.Destroy(debugger)

class LineNumberExtractor:
    def __init__(self):
        self.lldb = LLDBInterface.load()
        self.verifier = LineNumberVerifier(self.lldb)

    def get_line_nums(self, binary_file: str) -> Dict[str, List[int]]:
        try:
            source_files = DwarfDumpParser.get_source_files(binary_file)
            dwarfdump_output = DwarfDumpParser.run_dwarfdump(binary_file)
            file_table, line_info = DwarfDumpParser.parse_debug_line(dwarfdump_output)
            line_numbers_by_file = DwarfDumpParser.get_line_numbers_by_file(file_table, line_info)
            
            verified_line_numbers = {}
            for source_file, line_numbers in line_numbers_by_file.items():
                if source_file in source_files:  # Only verify for compile units
                    verified_lines = self.verifier.verify_line_nums(source_file, binary_file, line_numbers)
                    if verified_lines:
                        verified_line_numbers[source_file] = verified_lines
            
            return verified_line_numbers
        except Exception as e:
            logging.error(f"Error in get_line_nums: {str(e)}")
            return {}

def process_binary(extractor: LineNumberExtractor, binary_file: str) -> Tuple[str, Dict[str, List[int]]]:
    line_nums_by_file = extractor.get_line_nums(binary_file)
    return binary_file, line_nums_by_file

def main():
    if len(sys.argv) < 2:
        logging.error(f"Usage: {sys.argv[0]} <binary_file1> [<binary_file2> ...]")
        sys.exit(1)

    binary_files = sys.argv[1:]
    extractor = LineNumberExtractor()
    
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(process_binary, extractor, binary_file) for binary_file in binary_files]
        
        for future in as_completed(futures):
            binary_file, line_nums_by_file = future.result()
            if line_nums_by_file:
                logging.info(f"Results for {binary_file}:")
                for source_file, line_nums in line_nums_by_file.items():
                    logging.info(f"  Source file: {source_file}")
                    logging.info(f"  Line numbers: {line_nums}")
            else:
                logging.error(f"Failed to get line numbers for {binary_file}")

if __name__ == "__main__":
    main()
