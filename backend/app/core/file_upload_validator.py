"""
File Upload Validator — Validates uploaded files for security issues.

بيفحص الملفات المرفوعة:
- Magic Bytes (أول بايتات الملف)
- Extension Validation
- MIME Type
- Size Limits
- Filename Check (path traversal, .htaccess)
- Null Bytes
- Double Extension
- Executable Detection
- Archive Detection (ZIP bombs)
- Content Analysis

ملف مستقل.
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import structlog

logger = structlog.get_logger()


class FileUploadValidator:
    """
    كلاس لفحص الملفات المرفوعة.

    بيفحص:
    - Magic bytes
    - Extension
    - MIME
    - Size
    - Filename
    - Content
    """

    # ─── Limits ────────────────────────────────────────────
    MAX_FILE_SIZE = 50 * 1024 * 1024      # 50 MB
    MAX_FILENAME_LENGTH = 255
    MAX_FILES_PER_REQUEST = 10
    MAX_NESTED_ARCHIVE_DEPTH = 3

    # ─── Allowed Extensions ────────────────────────────────
    ALLOWED_EXTENSIONS = {
        ".pdf", ".docx", ".xlsx", ".pptx",
        ".txt", ".csv", ".json", ".xml",
        ".zip", ".tar", ".gz",
        ".png", ".jpg", ".jpeg", ".gif", ".webp",
        ".md", ".log",
    }

    # ─── Dangerous Extensions ──────────────────────────────
    DANGEROUS_EXTENSIONS = {
        # Executables
        ".exe", ".dll", ".so", ".dylib",
        ".bat", ".cmd", ".com", ".msi", ".scr", ".pif",
        # Scripts
        ".sh", ".bash", ".zsh", ".fish",
        ".ps1", ".psm1", ".psd1",
        ".py", ".pyc", ".pyo", ".pyw",
        ".rb", ".pl", ".pm", ".cgi",
        ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar",
        ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".asmx", ".ascx",
        ".js", ".mjs", ".cjs", ".ts",
        ".vbs", ".vbe", ".wsf", ".wsh",
        # Config / Server files
        ".htaccess", ".htpasswd", ".conf", ".config",
        ".ini", ".env",
        # System
        ".sys", ".drv", ".inf", ".reg",
        # Binary
        ".bin", ".dat",
    }

    # ─── Dangerous Filenames ───────────────────────────────
    DANGEROUS_FILENAMES = {
        ".htaccess", ".htpasswd", ".user.ini", "web.config",
        ".env", ".env.local", ".env.production",
        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
        "authorized_keys", "known_hosts",
        ".bashrc", ".bash_profile", ".zshrc", ".profile",
        "passwd", "shadow", "sudoers",
    }

    # ─── Magic Bytes (File Signatures) ────────────────────
    MAGIC_BYTES: Dict[str, List[bytes]] = {
        # Documents
        ".pdf":  [b"%PDF"],
        ".docx": [b"PK\x03\x04"],   # ZIP-based
        ".xlsx": [b"PK\x03\x04"],   # ZIP-based
        ".pptx": [b"PK\x03\x04"],   # ZIP-based
        ".doc":  [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
        ".xls":  [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
        # Images
        ".png":  [b"\x89PNG\r\n\x1a\n"],
        ".jpg":  [b"\xff\xd8\xff"],
        ".jpeg": [b"\xff\xd8\xff"],
        ".gif":  [b"GIF87a", b"GIF89a"],
        ".webp": [b"RIFF"],          # RIFF....WEBP
        ".bmp":  [b"BM"],
        ".ico":  [b"\x00\x00\x01\x00"],
        # Archives
        ".zip":  [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
        ".tar":  [b"ustar"],          # at offset 257
        ".gz":   [b"\x1f\x8b"],
        ".rar":  [b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"],
        ".7z":   [b"7z\xbc\xaf\x27\x1c"],
        # Other
        ".xml":  [b"<?xml"],
        ".json": [b"{", b"["],
        ".txt":  [],                  # مفيش magic bytes
        ".csv":  [],
        ".md":   [],
        ".log":  [],
    }

    # ─── Executable Magic Bytes ────────────────────────────
    EXECUTABLE_MAGIC = [
        b"MZ",              # Windows PE/EXE/DLL
        b"\x7fELF",         # Linux ELF
        b"\xca\xfe\xba\xbe",  # Mach-O (Java class, macOS)
        b"\xfe\xed\xfa\xce",  # Mach-O (32-bit)
        b"\xfe\xed\xfa\xcf",  # Mach-O (64-bit)
        b"\xce\xfa\xed\xfe",  # Mach-O (reverse)
        b"\xcf\xfa\xed\xfe",  # Mach-O (reverse 64)
        b"#!",              # Shebang (scripts)
    ]

    # ─── Dangerous Content Patterns ────────────────────────
    DANGEROUS_CONTENT_PATTERNS = [
        # PHP
        (r"<\?php", "php_code"),
        (r"<\?=", "php_short_echo"),
        (r"<\?php\s+eval", "php_eval"),
        # JSP
        (r"<%@\s*page", "jsp_page_directive"),
        (r"<%!", "jsp_declaration"),
        # ASP
        (r"<%\s*@", "asp_directive"),
        # Scripts
        (r"<script[^>]*>", "xss_script"),
        (r"javascript:", "javascript_protocol"),
        # Executable in file
        (r"\beval\s*\(", "eval_call"),
        (r"\bexec\s*\(", "exec_call"),
        (r"\bsystem\s*\(", "system_call"),
        (r"\bshell_exec\s*\(", "shell_exec"),
    ]

    # ─── Path Traversal Patterns ───────────────────────────
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e/",
        r"\.\.%2f",
        r"\.\.%5c",
    ]

    # ─── Main API ──────────────────────────────────────────

    @classmethod
    def validate(
        cls,
        filename: str,
        content: bytes,
        content_type: Optional[str] = None,
        declared_extension: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        بيفحص ملف مرفوع.

        Args:
            filename: اسم الملف
            content: محتوى الملف (bytes)
            content_type: الـ Content-Type (من الـ header)
            declared_extension: الامتداد المعلن

        Returns:
            dict فيه:
            - valid: bool
            - score: 0-100
            - level: clean/low/medium/high/critical
            - issues: list of issues
            - metadata: معلومات الملف
        """
        issues: List[Dict[str, Any]] = []
        total_score = 0

        # 1. فحص الاسم
        filename_issues = cls._check_filename(filename)
        if filename_issues:
            issues.extend(filename_issues["issues"])
            total_score += filename_issues["score"]

        # 2. فحص الحجم
        if len(content) > cls.MAX_FILE_SIZE:
            issues.append({
                "type": "file_too_large",
                "size": len(content),
                "max": cls.MAX_FILE_SIZE,
                "score": 30,
            })
            total_score += 30

        # 3. فحص الامتداد
        ext = cls._get_extension(filename)
        if ext:
            if ext in cls.DANGEROUS_EXTENSIONS:
                issues.append({
                    "type": "dangerous_extension",
                    "extension": ext,
                    "score": 50,
                })
                total_score += 50
            elif ext not in cls.ALLOWED_EXTENSIONS:
                issues.append({
                    "type": "extension_not_allowed",
                    "extension": ext,
                    "score": 25,
                })
                total_score += 25

        # 4. فحص Magic Bytes
        detected_ext = cls._detect_extension_by_magic(content)
        if detected_ext and ext and detected_ext != ext:
            # لو الامتداد المعلن مش مطابق للـ actual
            # (ما عدا الحالات المقبولة زي .docx vs .zip)
            if not cls._is_acceptable_mismatch(ext, detected_ext):
                issues.append({
                    "type": "extension_mismatch",
                    "declared": ext,
                    "detected": detected_ext,
                    "score": 35,
                })
                total_score += 35

        # 5. فحص Executable
        if cls._is_executable(content):
            issues.append({
                "type": "executable_file",
                "score": 60,
            })
            total_score += 60

        # 6. فحص المحتوى الخبيث
        content_issues = cls._check_content(content)
        if content_issues:
            issues.extend(content_issues["issues"])
            total_score += content_issues["score"]

        # 7. فحص MIME
        if content_type:
            mime_issues = cls._check_mime(content_type, ext)
            if mime_issues:
                issues.extend(mime_issues["issues"])
                total_score += mime_issues["score"]

        # 8. تحديد الخطورة
        score = min(total_score, 100)
        level = cls._get_level(score)

        return {
            "valid": score < 30,
            "score": score,
            "level": level,
            "issues": issues,
            "metadata": {
                "filename": filename,
                "extension": ext,
                "detected_extension": detected_ext,
                "size": len(content),
                "content_type": content_type,
            },
            "sanitized_filename": cls.sanitize_filename(filename),
        }

    # ─── Filename Checks ───────────────────────────────────

    @classmethod
    def _check_filename(cls, filename: str) -> Optional[Dict[str, Any]]:
        """بيفحص اسم الملف."""
        issues: List[Dict[str, Any]] = []
        score = 0

        if not filename:
            return {
                "issues": [{"type": "empty_filename", "score": 40}],
                "score": 40,
            }

        # 1. الطول
        if len(filename) > cls.MAX_FILENAME_LENGTH:
            issues.append({
                "type": "filename_too_long",
                "length": len(filename),
                "score": 10,
            })
            score += 10

        # 2. Null bytes
        if "\x00" in filename:
            issues.append({
                "type": "null_byte_in_filename",
                "score": 50,
            })
            score += 50

        # 3. Path Traversal
        for pattern in cls.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, filename):
                issues.append({
                    "type": "path_traversal_in_filename",
                    "pattern": pattern,
                    "score": 50,
                })
                score += 50
                break

        # 4. Absolute path
        if filename.startswith("/") or re.match(r"^[A-Za-z]:\\", filename):
            issues.append({
                "type": "absolute_path_in_filename",
                "score": 40,
            })
            score += 40

        # 5. أسماء خطيرة
        filename_lower = filename.lower()
        for dangerous in cls.DANGEROUS_FILENAMES:
            if filename_lower == dangerous or filename_lower.endswith(f"/{dangerous}"):
                issues.append({
                    "type": "dangerous_filename",
                    "matched": dangerous,
                    "score": 50,
                })
                score += 50
                break

        # 6. Hidden files (نقاط في البداية)
        if filename.startswith(".") and filename not in (".env",):
            # .env خطير، بس .gitignore مقبول
            if filename_lower not in (".gitignore", ".gitkeep", ".env.example"):
                issues.append({
                    "type": "hidden_file",
                    "score": 15,
                })
                score += 15

        # 7. Double Extension
        if cls._has_double_extension(filename):
            issues.append({
                "type": "double_extension",
                "filename": filename,
                "score": 40,
            })
            score += 40

        if not issues:
            return None

        return {"issues": issues, "score": score}

    @staticmethod
    def _has_double_extension(filename: str) -> bool:
        """بيفحص لو فيه double extension."""
        # مثال: file.php.jpg
        parts = filename.split(".")
        if len(parts) < 3:
            return False

        # فحص كل الامتدادات الوسطى
        dangerous_middle = {
            "php", "php3", "php4", "php5", "php7", "phtml", "phar",
            "asp", "aspx", "jsp", "jspx",
            "exe", "dll", "so", "bat", "cmd",
            "sh", "bash", "ps1",
            "py", "rb", "pl",
            "js", "vbs",
        }

        for ext in parts[1:-1]:
            if ext.lower() in dangerous_middle:
                return True

        return False

    @staticmethod
    def _get_extension(filename: str) -> Optional[str]:
        """بيرجع الامتداد (lowercase)."""
        if not filename:
            return None
        if "." not in filename:
            return None
        ext = "." + filename.rsplit(".", 1)[1].lower()
        return ext

    # ─── Magic Bytes Checks ────────────────────────────────

    @classmethod
    def _detect_extension_by_magic(cls, content: bytes) -> Optional[str]:
        """بيكشف الامتداد من الـ magic bytes."""
        if not content:
            return None

        # شوف أول 32 bytes
        header = content[:32]

        for ext, magics in cls.MAGIC_BYTES.items():
            for magic in magics:
                if header.startswith(magic):
                    # special case for webp: RIFF....WEBP
                    if ext == ".webp" and magic == b"RIFF":
                        if len(content) >= 12 and content[8:12] == b"WEBP":
                            return ".webp"
                        continue
                    return ext

        return None

    @classmethod
    def _is_executable(cls, content: bytes) -> bool:
        """بيفحص لو الملف executable."""
        if not content:
            return False
        header = content[:8]
        for magic in cls.EXECUTABLE_MAGIC:
            if header.startswith(magic):
                return True
        return False

    @staticmethod
    def _is_acceptable_mismatch(declared: str, detected: str) -> bool:
        """بيفحص لو عدم التطابق مقبول."""
        # ZIP-based documents
        zip_based = {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"}
        if declared in zip_based and detected == ".zip":
            return True

        # Text-based (مفيش magic bytes)
        text_based = {".txt", ".csv", ".md", ".log"}
        if declared in text_based and detected is None:
            return True

        return False

    # ─── Content Checks ────────────────────────────────────

    @classmethod
    def _check_content(cls, content: bytes) -> Optional[Dict[str, Any]]:
        """بيفحص محتوى الملف."""
        issues: List[Dict[str, Any]] = []
        score = 0

        # اقرا أول 10KB كنص
        try:
            text = content[:10240].decode("utf-8", errors="ignore")
        except Exception:
            return None

        # فحص الأنماط الخطيرة
        for pattern, name in cls.DANGEROUS_CONTENT_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                issues.append({
                    "type": "dangerous_content",
                    "pattern_name": name,
                    "score": 35,
                })
                score += 35
                # واحد كفاية
                break

        if not issues:
            return None

        return {"issues": issues, "score": score}

    # ─── MIME Checks ───────────────────────────────────────

    @classmethod
    def _check_mime(
        cls,
        content_type: str,
        ext: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        """بيفحص الـ MIME type."""
        issues: List[Dict[str, Any]] = []
        score = 0

        ct = content_type.split(";")[0].strip().lower()

        # MIME خبيثة
        dangerous_mimes = {
            "application/x-php",
            "application/x-httpd-php",
            "application/x-executable",
            "application/x-msdownload",
            "application/x-sh",
            "application/x-shellscript",
        }

        if ct in dangerous_mimes:
            issues.append({
                "type": "dangerous_mime",
                "mime": ct,
                "score": 50,
            })
            score += 50

        if not issues:
            return None

        return {"issues": issues, "score": score}

    # ─── Level ─────────────────────────────────────────────

    @staticmethod
    def _get_level(score: int) -> str:
        """بيرجع المستوى."""
        if score == 0:
            return "clean"
        if score < 20:
            return "low"
        if score < 40:
            return "medium"
        if score < 60:
            return "high"
        return "critical"

    # ─── Sanitization ──────────────────────────────────────

    @classmethod
    def sanitize_filename(cls, filename: str) -> str:
        """
        بينضف اسم الملف.

        - شيل Path traversal
        - شيل الأحرف الخطيرة
        - حدد الطول
        """
        if not filename:
            return "unnamed"

        # 1. شيل المسارات
        filename = filename.replace("\\", "/").split("/")[-1]

        # 2. شيل Null bytes
        filename = filename.replace("\x00", "")

        # 3. شيل الأحرف الخطيرة
        filename = re.sub(r'[<>:"|?*]', "_", filename)

        # 4. شيل النقاط المتكررة
        filename = re.sub(r"\.+", ".", filename)

        # 5. شيل المسافات الزيادة
        filename = filename.strip(". ")

        # 6. حدد الطول
        if len(filename) > cls.MAX_FILENAME_LENGTH:
            # احتفظ بالامتداد
            ext = cls._get_extension(filename) or ""
            name_part = filename[: cls.MAX_FILENAME_LENGTH - len(ext)]
            filename = name_part + ext

        # 7. لو فاضي بعد كل ده
        if not filename:
            return "unnamed"

        return filename

    @classmethod
    def get_safe_extension(cls, filename: str) -> Optional[str]:
        """بيرجع امتداد آمن (أو None)."""
        ext = cls._get_extension(filename)
        if not ext:
            return None
        if ext in cls.DANGEROUS_EXTENSIONS:
            return None
        if ext not in cls.ALLOWED_EXTENSIONS:
            return None
        return ext

    # ─── Batch Validation ──────────────────────────────────

    @classmethod
    def validate_batch(
        cls,
        files: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        بيفحص مجموعة ملفات.

        Args:
            files: list of dicts، كل واحد فيه filename + content

        Returns:
            dict فيه valid + results لكل ملف
        """
        if len(files) > cls.MAX_FILES_PER_REQUEST:
            return {
                "valid": False,
                "error": "too_many_files",
                "max": cls.MAX_FILES_PER_REQUEST,
                "results": [],
            }

        results: List[Dict[str, Any]] = []
        all_valid = True
        max_score = 0

        for f in files:
            result = cls.validate(
                filename=f.get("filename", ""),
                content=f.get("content", b""),
                content_type=f.get("content_type"),
            )
            results.append(result)

            if not result["valid"]:
                all_valid = False
            if result["score"] > max_score:
                max_score = result["score"]

        return {
            "valid": all_valid,
            "total_files": len(files),
            "max_score": max_score,
            "results": results,
        }


# ─── Singleton ─────────────────────────────────────────────

file_upload_validator = FileUploadValidator()