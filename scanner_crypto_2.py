import os
from typing import Dict, List, Union, Optional

class ASTNode:
    """
    A simple class to represent nodes in a manually constructed Abstract Syntax Tree (AST).
    """
    def __init__(self, node_type: str, value: Optional[str] = None, line_num: Optional[int] = None):
        self.node_type = node_type
        self.value = value
        self.line_num = line_num
        self.children = []

    def add_child(self, child: 'ASTNode') -> None:
        self.children.append(child)

    def traverse(self) -> List[tuple]:
        """
        Perform pre-order traversal of the AST and return a list of visited node values.
        """
        visited_nodes = []
        visited_nodes.append((self.line_num, self.value))
        for child in self.children:
            visited_nodes.extend(child.traverse())
        return visited_nodes

def build_ast_from_code(code_lines: List[str]) -> ASTNode:
    """
    Builds a simple AST from the given code lines.
    """
    root = ASTNode(node_type="ROOT", value="ROOT", line_num=0)
    for line_num, line in enumerate(code_lines, start=1):
        line_node = ASTNode(node_type="LINE", value=line.strip(), line_num=line_num)
        root.add_child(line_node)
    return root

class CryptoVulnerabilityScanner:
    def __init__(self):
        self.vulnerability_patterns = {
            "c": {
                "Weak Cipher (DES/ECB)": ["EVP_EncryptInit_ex(ctx, EVP_des_ecb()"],
                "Missing IV (Static IV)": [
                    "unsigned char iv[16] = {0}",
                    "std::vector<unsigned char> iv(16, 0);"
                ],
                "Hardcoded Keys": ["unsigned char key[16] =", "char key[16] =", "unsigned char key[]"],
                "Using ECB Mode": ["EVP_aes_128_ecb()", "EVP_aes_256_ecb()"],
                "Weak Hash Functions": ["EVP_md5()", "EVP_sha1()"],
                "Missing Salt": ["EVP_DigestInit_ex(ctx, EVP_md5(), NULL)"],
                "Weak Key Derivation": ["EVP_Digest", "EVP_sha256()"],
                "No Integrity Check": ["EVP_aes_cbc()", "EVP_EncryptFinal_ex"]
            },
            "java": {
                "Weak Cipher (DES/ECB)": ["Cipher.getInstance(\"DES/ECB\")"],
                "Missing IV (Static IV)": ["new IvParameterSpec(new byte[16])"],
                "Hardcoded Keys": ["String key = \"", "SecretKeySpec key = new SecretKeySpec(\""],
                "Using ECB Mode": ["Cipher.getInstance(\"AES/ECB\")"],
                "Weak Hash Functions": ["MessageDigest.getInstance(\"MD5\")", "MessageDigest.getInstance(\"SHA-1\")"],
                "Missing Salt": ["new PBEKeySpec(password.toCharArray())"],
                "Weak Key Derivation": ["password.toCharArray()"]
            },
            "python": {
                "Weak Cipher (DES/ECB)": ["DES.new(", "Cipher(algorithms.DES"],
                "Missing IV (Static IV)": ["iv = bytes(16)", "iv = b'\\x00' * 16"],
                "Hardcoded Keys": ["key = b'", "key = '", "key = bytes("],
                "Using ECB Mode": ["AES.MODE_ECB"],
                "Weak Hash Functions": ["hashlib.md5(", "hashlib.sha1("],
                "Missing Salt": ["hashlib.pbkdf2_hmac("],
                "Weak Key Derivation": ["pbkdf1_derive("]
            },
            "javascript": {
                "Weak Cipher (DES/ECB)": ["DES", "crypto.createCipheriv('des-ede3',"],
                "Missing IV (Static IV)": ["const iv = Buffer.from('0000000000000000', 'hex')"],
                "Hardcoded Keys": ["const key = '", "const key = Buffer.from("],
                "Using ECB Mode": ["crypto.createCipheriv('aes-128-ecb',"],
                "Weak Hash Functions": ["crypto.createHash('md5')", "crypto.createHash('sha1')"],
                "Missing Salt": ["crypto.pbkdf2Sync("],
                "Weak Key Derivation": ["crypto.pbkdf1Sync("]
            },
            "php":{
                "Weak Cipher (DES/ECB)": ["openssl_encrypt($data, 'DES-ECB'", "openssl_decrypt($data, 'DES-ECB'"],
             "Missing IV (Static IV)": ["openssl_encrypt($data, 'AES-ECB'", "openssl_decrypt($data, 'AES-ECB'"],
        "Hardcoded Keys": ["$key = \"", "$key = '", "new \\DateTimeImmutable($key)"],
        "Using ECB Mode": ["openssl_encrypt($data, 'AES-ECB'", "openssl_decrypt($data, 'AES-ECB'"],
        "Weak Hash Functions": ["md5(", "sha1("],
        "Missing Salt": ["openssl_pbkdf2($password, '',"],
        "Weak Key Derivation (PBKDF1)": ["password_hash($password, PASSWORD_DEFAULT)"],
        "No Integrity Check": ["openssl_encrypt($data, 'AES-CBC'", "openssl_decrypt($data, 'AES-CBC'"],
        "Deprecated Algorithms": ["RC4", "DES"],
        "Hardcoded Secrets": ["$password = \"", "$secret = \""],
        "Insufficient Key Length": ["openssl_encrypt($data, 'AES-128-ECB'", "openssl_decrypt($data, 'AES-128-ECB'"],
        "Failure to Verify Certificates": ["'verify_peer' => false", "'verify_peer_name' => false"],
        "Deprecated RC4 Usage": ["openssl_encrypt($data, 'RC4'", "openssl_decrypt($data, 'RC4'"],
        "Ignoring Exceptions": ["catch (Exception $e) {", "catch (Throwable $t) {"],
        "Encrypting Known Plaintext": ["$plaintext = 'test data'"],
        "Static Key Derivation": ["new \\SecretKeySpec($key, 'AES')"],
        "Using Weak PRNGs": ["rand()", "mt_rand()", "mt_srand()"],
        "Reusing Nonce": ["openssl_encrypt($data, 'AES-CBC'", "openssl_decrypt($data, 'AES-CBC'"],
        "Insecure Communication Protocol": ["new URL('http://')"],
        "Missing Agile Encryption": ["openssl_encrypt($data, 'AES-ECB'"]
            }
        }

    def detect_language(self, file_extension: str) -> str:
        extension_map = {
            '.c': 'c',
            '.cpp': 'c',
            '.h': 'c',
            '.java': 'java',
            '.py': 'python',
            '.js': 'javascript',
            'php':'php '
        }
        return extension_map.get(file_extension.lower(), 'unknown')

    def scan_file(self, file_path: str) -> Dict[str, List[str]]:
        """
        Scans a single file for cryptographic vulnerabilities.
        """
        try:
            _, file_extension = os.path.splitext(file_path)
            language = self.detect_language(file_extension)
            
            if language == 'unknown':
                return {"error": [f"Unsupported file type: {file_extension}"]}

            with open(file_path, 'r', encoding='utf-8') as file:
                code_lines = file.readlines()

            ast_root = build_ast_from_code(code_lines)
            detected_issues: Dict[str, List[str]] = {}
            
            patterns = self.vulnerability_patterns[language]
            for vulnerability_type, pattern_list in patterns.items():
                issues = []
                for pattern in pattern_list:
                    for line_num, line_value in ast_root.traverse():
                        if pattern in line_value:
                            # Context-aware scanning
                            if self._should_report_issue(vulnerability_type, pattern, line_value, code_lines, line_num):
                                issues.append(f"Line {line_num}: {pattern}")
                
                if issues:
                    detected_issues[vulnerability_type] = issues

            return detected_issues

        except Exception as e:
            return {"error": [str(e)]}

    def _should_report_issue(self, vulnerability_type: str, pattern: str, line_value: str, 
                           code_lines: List[str], line_num: int) -> bool:
        """
        Determines whether an issue should be reported based on context.
        """
        # Skip safe usage patterns
        if vulnerability_type == "Weak Key Derivation" and pattern == "EVP_sha256()":
            if any("EVP_sha512()" in line for line in code_lines):
                return False

        if vulnerability_type == "Missing Salt" and "salt" in ''.join(
            code_lines[max(0, line_num-2):min(len(code_lines), line_num+2)]):
            return False

        if vulnerability_type == "Missing IV" and "random" in line_value.lower():
            return False

        if vulnerability_type == "Hardcoded Keys" and "getenv" in line_value:
            return False

        return True

# Function to be used in the API
def scan_crypto_vulnerabilities(file_path: str) -> Dict[str, Union[List[str], Dict[str, List[str]]]]:
    """
    Main function to be called from the API to scan for cryptographic vulnerabilities.
    """
    scanner = CryptoVulnerabilityScanner()
    results = scanner.scan_file(file_path)
    
    if "error" in results:
        return {"status": "error", "messages": results["error"]}
    
    return {
        "status": "success",
        "vulnerabilities": results
    }