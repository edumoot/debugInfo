import subprocess
from pathlib import Path
import logging
import re
import tempfile
import shutil
import os
from contextlib import contextmanager
from typing import List, Tuple, Optional
from functools import lru_cache

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@contextmanager
def temp_directory():
    temp_dir = tempfile.mkdtemp()
    try:
        yield Path(temp_dir)
    finally:
        shutil.rmtree(temp_dir)

@lru_cache(maxsize=128)
def get_cc_output(cc: str, file: Path, flags: str, cc_timeout: int) -> Tuple[int, str]:
    cmd = [
        cc,
        str(file),
        "-c",
        "-o/dev/null",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-O3",
        "-Wno-builtin-declaration-mismatch",
        "-I/usr/local/include/",
    ] + flags.split()
    
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=cc_timeout, text=True)
        return result.returncode, result.stdout
    except subprocess.TimeoutExpired:
        return 1, ""
    except subprocess.CalledProcessError:
        return 1, ""

def check_compiler_warnings(clang: str, gcc: str, file: Path, flags: str, cc_timeout: int) -> bool:
    clang_rc, clang_output = get_cc_output(clang, file, flags, cc_timeout)
    gcc_rc, gcc_output = get_cc_output(gcc, file, flags, cc_timeout)

    if clang_rc != 0 or gcc_rc != 0:
        return False

    warnings = [
        "conversions than data arguments",
        "incompatible redeclaration",
        "ordered comparison between pointer",
        "eliding middle term",
        "end of non-void function",
        "invalid in C99",
        "specifies type",
        "should return a value",
        "uninitialized",
        "incompatible pointer to",
        "incompatible integer to",
        "comparison of distinct pointer types",
        "type specifier missing",
        "uninitialized",
        "Wimplicit-int",
        "division by zero",
        "without a cast",
        "control reaches end",
        "return type defaults",
        "cast from pointer to integer",
        "useless type name in empty declaration",
        "no semicolon at end",
        "type defaults to",
        "too few arguments for format",
        "incompatible pointer",
        "ordered comparison of pointer with integer",
        "declaration does not declare anything",
        "expects type",
        "comparison of distinct pointer types",
        "pointer from integer",
        "incompatible implicit",
        "excess elements in struct initializer",
        "comparison between pointer and integer",
        "return type of 'main' is not 'int'",
        "past the end of the array",
        "no return statement in function returning non-void",
        "undefined behavior",
    ]

    return not any(w in clang_output or w in gcc_output for w in warnings)

@lru_cache(maxsize=128)
def use_ub_sanitizers(clang: str, file: Path, flags: str, cc_timeout: int, exe_timeout: int) -> bool:
    cmd = [clang, str(file), "-O0", "-fsanitize=undefined,address"] + flags.split()

    with temp_directory() as tmpdir:
        binary = tmpdir / "test.out"
        cmd.append(f"-o{binary}")
        
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=cc_timeout, check=True)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return False

        try:
            subprocess.run(str(binary), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=exe_timeout, check=True)
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return False

def sanitize(gcc: str, clang: str, file: Path, flags: str, cc_timeout: int = 8, exe_timeout: int = 2) -> bool:
    return (check_compiler_warnings(gcc, clang, file, flags, cc_timeout) and
            use_ub_sanitizers(clang, file, flags, cc_timeout, exe_timeout))

class Checker:
    def __init__(self):
        self.gcc = "gcc"
        self.clang = "clang"
        self.llvm_dwarfdump = "llvm-dwarfdump"
        self.llvm_objdump = "llvm-objdump"

    def is_without_undefined_behavior(self, case: Path) -> bool:
        return sanitize(self.gcc, self.clang, case, "-g")

    @lru_cache(maxsize=128)
    def static_check(self, file_path: Path) -> Tuple[bool, bool, bool, bool]:
        with open(file_path, 'r') as f:
            code = f.read()
        return (
            '*' in code,
            'struct' in code,
            'union' in code,
            bool(re.search(r'\w+\s*\[[^\]]*\]', code))
        )

    @lru_cache(maxsize=128)
    def dynamic_check(self, file_path: Path) -> Tuple[bool, bool, bool, bool]:
        with temp_directory() as temp_dir:
            binary_file = temp_dir / "test_program"
            cmd = [self.clang, "-I/usr/local/include/", "-g", "-O2", str(file_path), "-o", str(binary_file)]
            
            try:
                subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                return False, False, False, False

            dwarfdump_cmd = [self.llvm_dwarfdump, "--debug-info", str(binary_file) + ".dSYM"]
            dwarfdump_output = subprocess.run(dwarfdump_cmd, capture_output=True, text=True).stdout

            return (
                "*" in dwarfdump_output or "DW_TAG_pointer_type" in dwarfdump_output,
                "DW_TAG_structure_type" in dwarfdump_output,
                "DW_TAG_union_type" in dwarfdump_output,
                "DW_TAG_array_type" in dwarfdump_output
            )

    def is_interesting_with_pointers(self, case: Path) -> bool:
        return self.static_check(case)[0] and self.dynamic_check(case)[0]

    def is_interesting_with_arrays(self, case: Path) -> bool:
        return self.static_check(case)[3] and self.dynamic_check(case)[3]

    def is_interesting_with_elements(self, case: Path) -> bool:
        return any(self.static_check(case)) and any(self.dynamic_check(case))

    def is_interesting(self, case: Path) -> bool:
        return (self.is_without_undefined_behavior(case) and
                self.is_interesting_with_pointers(case))

if __name__ == "__main__":
    checker = Checker()
    case = Path("test.c")
    
    if checker.is_without_undefined_behavior(case):
        print("The case is UB free!")
    else:
        print("The case has UBs.")
    
    if checker.is_interesting_with_pointers(case):
        print("The case has pointers!")
    else:
        print("The case has no pointers.")
