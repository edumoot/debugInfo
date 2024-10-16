import os
import subprocess
import concurrent.futures
import hashlib
import shutil
import time
import multiprocessing
import tempfile
from typing import List, Dict, Any, Tuple, Optional
import itertools
from pathlib import Path
import logging
from dataclasses import dataclass, field

from utils import LineNumberExtractor, get_compiler_version, find_c_files, find_c_files_int
from get_debug_values import get_debug_values


@dataclass
class CompilerConfig:
    compiler_path: str
    opt_levels: List[str] = field(default_factory=lambda: ['0', '1', '2', '3', 's', 'z'])
    dbg_levels: List[str] = field(default_factory=lambda: ['1', '2', '3'])
  

# @dataclass
# class BinaryConfig:
#     hash_algorithm: str = "sha256"

@dataclass
class AnalysisConfig:
    evidence_dir: Path
    analysis_timeout: int = 300  # seconds

@dataclass
class ParallelConfig:
    max_workers: int = field(default_factory=lambda: multiprocessing.cpu_count())


class Binary:
    def __init__(self, 
                 compiler_config: CompilerConfig, 
                 source_path: Path, 
                 output_dir: Path,
                 optimization_level: str, 
                 debug_level: str ):
        self.compiler_path = compiler_config.compiler_path
        self.source_path = source_path
        self.optimization_level = optimization_level
        self.debug_level = debug_level
        self.file_name = f"{source_path.stem}_O{optimization_level}_D{debug_level}.out"
        self.file_path = Path(output_dir) / self.file_name
        self.hash_value = None
        self.line_numbers = {}  # Dict[str, List[int]] to handle multiple source files
        self.hash_algorithm: str = "sha256"
  
    def generate_binary(self) ->bool:
        cmd = [
            self.compiler_path,
            str(self.source_path),
            "-I/usr/local/include",
            f"-O{self.optimization_level}",
            f"-g{self.debug_level}",
            "-o", str(self.file_path)]
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.compute_hash()
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to compile {self.source_path} with optimization level -O{self.optimization_level} and -g{self.debug_level}")
            logging.error(e)
            return False    

    def compute_hash(self) -> None:
        with open(self.file_path, 'rb') as f:
            # self.hash_value = hashlib.md5(f.read()).hexdigest()
            self.hash_value = hashlib.new(self.hash_algorithm, f.read()).hexdigest()
 
    def get_line_numbers(self) -> None:
        try:
            extractor = LineNumberExtractor()
            self.line_numbers = extractor.get_line_nums(str(self.file_path))
            # logging.info(f"Line numbers for {self.file_name}: {self.line_numbers}")
        except Exception as e:
            logging.error(f"Error extracting line numbers for {self.file_name}: {str(e)}")
            self.line_numbers = {}

    def cleanup(self):
        if self.file_path.exists():
            self.file_path.unlink()
        # Clear any other resources if necessary
        self.line_numbers.clear()

class BinaryAnalyzer:
    def __init__(self, 
                 compiler_config: CompilerConfig, 
                 analysis_config: AnalysisConfig,
                 source_path: Path,
                 output_dir: Path):
        self.compiler_config = compiler_config
        self.analysis_config = analysis_config
        self.source_path = source_path
        self.output_dir = Path(output_dir)
        self.evidence_dir = analysis_config.evidence_dir    
        self.source_dir = self.source_path.parent #Path(os.path.dirname(source_file))
        self.binaries = []
          
    def _generate_binary(self, opt_level, debug_level) -> Optional[Binary]:
        binary = Binary(self.compiler_config, self.source_path, self.output_dir, opt_level, debug_level)
        if binary.generate_binary():
            return binary
        else:
            return None
    
    def generate_variants(self):
        file_hashes = set()
        for opt_level in self.compiler_config.opt_levels:
            for debug_level in self.compiler_config.dbg_levels:
                binary = self._generate_binary(opt_level, debug_level)
                if binary and binary.hash_value not in file_hashes:
                    # print(binary.hash_value)
                    self.binaries.append(binary)
                    file_hashes.add(binary.hash_value)
         
    @staticmethod
    def _get_line_numbers(binary: Binary):
        binary.get_line_numbers()
        return binary
    
    def get_line_numbers(self):
        with concurrent.futures.ProcessPoolExecutor() as executor:
            self.binaries = list(executor.map(self._get_line_numbers, self.binaries))

    @staticmethod
    def _find_issues_type1_2(binary):
        binary_issues = []
        for source_file, lines in binary.line_numbers.items():
            for line in lines:
                debug_values = get_debug_values(source_file, str(binary.file_path), line)
                for debug_value in debug_values:
                    if debug_value.is_pointer():
                        print(f"{binary.file_name} {source_file} {line}: {debug_value}")
                    if debug_value.error_message and not debug_value.is_known_error():
                        issue = {
                            'binary': binary.file_name,
                            'source_file': source_file,
                            'line': line,
                            'error_message': f"{debug_value.name} - {debug_value.error_message}"
                        }
                        binary_issues.append(issue)
                        print(f"{binary.file_name} {source_file} {line}: {debug_value}")
                    if debug_value.is_pointer() and debug_value.error_message:
                        issue = {
                            'binary': binary.file_name,
                            'source_file': source_file,
                            'line': line,
                            'error_message': f"{debug_value.name} - {debug_value.error_message}"
                        }
                        binary_issues.append(issue)
                        print(f"{binary.file_name} {source_file} {line}: {debug_value}")
        return binary_issues

    def find_issues_type1_2(self):
        with multiprocessing.Pool() as pool:
            results = pool.map(self._find_issues_type1_2, self.binaries)
        issues = [issue for binary_issues in results for issue in binary_issues]
        if issues:
            self._write_results(issues)
        else:
            print(f"{os.path.basename(self.source_path)} No issues found. Skipping result writing.")

    def _write_results(self, issues: List[Dict[str, str]]):
        # Group issues by source file
        issues_by_file = {}
        for issue in issues:
            source_file = issue['source_file']
            if source_file not in issues_by_file:
                issues_by_file[source_file] = []
            issues_by_file[source_file].append(issue)

        # Write results for each source file
        for source_file, file_issues in issues_by_file.items():
            source_file = Path(source_file)
            # Copy source file to evidence directory
            shutil.copy2(self.source_dir / source_file, self.evidence_dir/source_file)
            
            # Write results as comments at the end of the source file
            with (self.evidence_dir / source_file.name).open('a') as f:
                f.write(f"\n\n//LLVM{get_compiler_version('clang')} {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}\n")
                for issue in file_issues:
                    f.write(f"// {issue['binary']} {issue['line']}: {issue['error_message']}\n")
                f.write("\n")

        # Copy unique binaries with issues to evidence directory
        unique_binaries = set(issue['binary'] for issue in issues)
        for binary_name in unique_binaries:
            binary = next((b for b in self.binaries if b.file_name == binary_name), None)
            if binary:
                shutil.copy2(binary.file_path, self.evidence_dir / binary_name)
            else:
                print(f"Warning: Binary {binary_name} not found")


    #  def find_issues_type3(self):
    #     issues = {}
    #     binary_pairs = list(itertools.combinations(self.binaries, 2))
    #     for binary1, binary2 in binary_pairs:
    #         for source_file in set(binary1.line_numbers.keys()) & set(binary2.line_numbers.keys()):
    #             common_lines = set(binary1.line_numbers[source_file]) & set(binary2.line_numbers[source_file])
    #             for line in common_lines:
    #                 debug_values1 = get_debug_values(source_file, binary1.file_path, line)
    #                 debug_values2 = get_debug_values(source_file, binary2.file_path, line)
    #                 for debug_value1 in debug_values1:
    #                     for debug_value2 in debug_values2:
    #                         if debug_value1.name == debug_value2.name:
    #                             issues[] = debug_value1.compare(debug_value2)
    #                             if
            
    def cleanup(self):
        for binary in self.binaries:
            binary.cleanup()
        self.binaries.clear()
        # Remove the output directory if it's empty
        if self.output_dir.exists() and not any(self.output_dir.iterdir()):
            self.output_dir.rmdir()
   
class SingleSourceAnalysis:
    def __init__(self,
                compiler_config: CompilerConfig,
                analysis_config: AnalysisConfig, 
                source_path: Path ):
        self.compiler_config = compiler_config
        self.analysis_config = analysis_config
        self.source_file = source_path
        self.output_dir = None
        self.analyzer = None

    def run_analysis(self):
        with tempfile.TemporaryDirectory() as temp_output_dir:
            self.output_dir = Path(temp_output_dir)
            self.analyzer = BinaryAnalyzer(self.compiler_config, self.analysis_config, 
                                           self.source_file, self.output_dir)
            self.analyzer.generate_variants()
            self.analyzer.get_line_numbers()
            self.analyzer.find_issues_type1_2()

    def cleanup(self):
        if self.analyzer:
            self.analyzer.cleanup()
        self.analyzer = None
        self.temp_dir = None
        
class ParallelSourceAnalysis:
    def __init__(self, 
                 compiler_config: CompilerConfig,  
                 analysis_config: AnalysisConfig, 
                 parallel_config: ParallelConfig, 
                 source_files: List[Path]):
        self.compiler_config = compiler_config
        self.analysis_config = analysis_config
        self.parallel_config = parallel_config
        self.source_files = source_files

    def analyze_single_source(self, source_file: Path):
        analysis = SingleSourceAnalysis(self.compiler_config, self.analysis_config, source_file)
        try:
            analysis.run_analysis()
        finally:
            analysis.cleanup()
        return source_file

    def run_parallel_analysis(self):
        with concurrent.futures.ProcessPoolExecutor(max_workers=self.parallel_config.max_workers) as executor:
            results = list(executor.map(self.analyze_single_source, self.source_files))
        return results

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    compiler_config = CompilerConfig(compiler_path="clang")
    analysis_config = AnalysisConfig(evidence_dir=Path("./evidence"))
    parall_config = ParallelConfig(max_workers=12)
    # source_file = Path("case2.c")
    # single_source_code_analysis = SingleSourceAnalysis(compiler_config, analysis_config, source_file)
    # single_source_code_analysis.run_analysis()
    source_dir = "./"
    source_files = find_c_files(source_dir)
    # source_files = [Path("case.c"), Path("case2.c"), Path("case6.c"), Path("case7.c"), Path("case8.c")]
    # for file in source_files:
    #     print(file)
   
    parall_analysis = ParallelSourceAnalysis(compiler_config, analysis_config, parall_config, source_files)
    parall_analysis.run_parallel_analysis()



  
        
