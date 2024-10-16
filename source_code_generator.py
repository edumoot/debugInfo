import tempfile
import subprocess
import logging
import os
import sys
import multiprocessing
from random import randint
from pathlib import Path
from typing import Optional, List, Tuple
from tempfile import NamedTemporaryFile
from concurrent.futures import ProcessPoolExecutor, as_completed

class CompilationEnvironment:
    def __init__(self) -> None:
        self.temp_dir: Optional[tempfile.TemporaryDirectory] = None

    def __enter__(self) -> Path:
        self.temp_dir = tempfile.TemporaryDirectory()
        tempfile.tempdir = self.temp_dir.name
        return Path(self.temp_dir.name)

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        tempfile.tempdir = None
        if self.temp_dir:
            self.temp_dir.cleanup()

class Compiler:
    @staticmethod
    def run_command(cmd: List[str], timeout: int) -> Tuple[int, str]:
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, text=True)
            return result.returncode, result.stdout
        except subprocess.TimeoutExpired:
            return 1, "Compilation timed out"
        except subprocess.CalledProcessError as e:
            return e.returncode, e.output

    @staticmethod
    def check_warnings(cfile: Path, flags: str, timeout: int) -> bool:
        cmd = [
            "clang", str(cfile), "-c", "-o/dev/null", "-Wall", "-Wextra", "-Wpedantic",
            "-O3", "-Wno-builtin-declaration-mismatch"
        ]
        if flags:
            cmd.extend(flags.split())
        
        returncode, output = Compiler.run_command(cmd, timeout)
        if returncode != 0:
            return False

        warnings = [
            "conversions than data arguments", "incompatible redeclaration",
            "ordered comparison between pointer", "eliding middle term",
            "end of non-void function", "invalid in C99", "specifies type",
            "should return a value", "uninitialized", "incompatible pointer to",
            "incompatible integer to", "comparison of distinct pointer types",
            "type specifier missing", "Wimplicit-int", "division by zero",
            "without a cast", "control reaches end", "return type defaults",
            "cast from pointer to integer", "useless type name in empty declaration",
            "no semicolon at end", "type defaults to", "too few arguments for format",
            "incompatible pointer", "ordered comparison of pointer with integer",
            "declaration does not declare anything", "expects type",
            "pointer from integer", "incompatible implicit",
            "excess elements in struct initializer",
            "comparison between pointer and integer",
            "return type of 'main' is not 'int'", "past the end of the array",
            "no return statement in function returning non-void",
            "undefined behavior"
        ]

        return not any(w in output for w in warnings)

    @staticmethod
    def use_sanitizers(cfile: Path, flags: str, cc_timeout: int, exe_timeout: int) -> bool:
        with CompilationEnvironment() as temp_dir:
            exe_path = temp_dir / "test.out"
            compile_cmd = ["clang", str(cfile), "-O0", "-fsanitize=undefined,address", f"-o{exe_path}"]
            if flags:
                compile_cmd.extend(flags.split())
            
            returncode, _ = Compiler.run_command(compile_cmd, cc_timeout)
            if returncode != 0:
                return False
            
            exe_cmd = [str(exe_path)]
            returncode, _ = Compiler.run_command(exe_cmd, exe_timeout)
            return returncode == 0

    @staticmethod
    def verify_with_compcert(cfile: Path, flags: str, timeout: int) -> bool:
        cmd = ["ccomp", str(cfile), "-interp", "-fall"]
        if flags:
            cmd.extend(flags.split())
        
        returncode, _ = Compiler.run_command(cmd, timeout)
        return returncode == 0

class CodeGenerator:
    @staticmethod
    def run_csmith() -> str:
        options = [
            "arrays", "bitfields", "checksum", "comma-operators",
            "compound-assignment", "consts", "divs", "embedded-assigns",
            "jumps", "longlong", "force-non-uniform-arrays", "math64",
            "muls", "packed-struct", "paranoid", "pointers", "structs",
            "inline-function", "return-structs", "arg-structs",
            "dangling-global-pointers"
        ]

        cmd = [
            "csmith", "--no-unions", "--safe-math", "--no-argc",
            "--no-volatiles", "--no-volatile-pointers"
        ]
        cmd.extend(f"--{'no-' if randint(0, 1) else ''}{option}" for option in options)

        for _ in range(10):  # Try up to 10 times
            returncode, output = Compiler.run_command(cmd, timeout=30)
            if returncode == 0:
                return output
        
        raise RuntimeError("CSmith failed 10 times in a row!")

    @staticmethod
    def generate_interesting_case(min_size: int = 4000, max_size: int = 30000, 
                                  additional_flags: str = "") -> str:
        while True:
            try:
                candidate = CodeGenerator.run_csmith()
                if min_size <= len(candidate) <= max_size:
                    with NamedTemporaryFile(suffix=".c", mode='w') as ntf:
                        ntf.write(candidate)
                        ntf.flush()
                        if Sanitizer.sanitize(Path(ntf.name), additional_flags):
                            return candidate
                        
            except subprocess.TimeoutExpired:
                logging.warning("Timeout occurred during code generation")

class Sanitizer:
    @staticmethod
    def sanitize(file: Path, flags: str, cc_timeout: int = 8, exe_timeout: int = 2, 
                 compcert_timeout: int = 16) -> bool:
        try:
            return all([
                Compiler.check_warnings(file, flags, cc_timeout),
                Compiler.use_sanitizers(file, flags, cc_timeout, exe_timeout),
                Compiler.verify_with_compcert(file, flags, compcert_timeout)
            ])
        except subprocess.TimeoutExpired:
            return False

# def main():
#     logging.basicConfig(level=logging.INFO)
#     output_dir = Path("generated_code")
#     output_dir.mkdir(exist_ok=True)

#     for i in range(100):
#         try:
#             source_code = CodeGenerator.generate_interesting_case()
#             output_file = output_dir / f"generated_{i:03d}.c"
#             with open(output_file, 'w') as f:
#                 f.write(source_code)
#             logging.info(f"Generated and saved: {output_file}")
#         except Exception as e:
#             logging.error(f"Error generating case {i}: {str(e)}")

# if __name__ == '__main__':
#     main()

class ParallelCodeGenerator:
    def __init__(self, output_dir: Path, num_processes: int = None):
        self.output_dir = output_dir
        self.num_processes = num_processes or multiprocessing.cpu_count()
        self.output_dir.mkdir(exist_ok=True)

    def generate_file(self, file_index: int) -> Tuple[int, Optional[str]]:
        try:
            source_code = CodeGenerator.generate_interesting_case()
            output_file = self.output_dir / f"d_{file_index:05d}.c"
            with open(output_file, 'w') as f:
                f.write(source_code)
            return file_index, None
        except Exception as e:
            return file_index, str(e)

    def generate_files(self, num_files: int):
        logging.info(f"Generating {num_files} files using {self.num_processes} processes")
        with ProcessPoolExecutor(max_workers=self.num_processes) as executor:
            futures = [executor.submit(self.generate_file, i) for i in range(num_files)]
            for future in as_completed(futures):
                file_index, error = future.result()
                if error:
                    logging.error(f"Error generating file {file_index}: {error}")
                else:
                    logging.info(f"Successfully generated file {file_index}")

def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    output_dir = Path("generated_code")
    num_files = 100  # Change this to the desired number of files

    generator = ParallelCodeGenerator(output_dir)
    generator.generate_files(num_files)

if __name__ == '__main__':
    main()