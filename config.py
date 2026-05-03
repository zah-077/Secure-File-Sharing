import os

class Config:
    """Application configuration with security-focused settings."""

    # Flask secret key for session management
    SECRET_KEY = os.environ.get('SECRET_KEY', 'sfk-proj-2024-secure-key-change-in-production')

    # Database configuration (SQLite for prototype)
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'secure_file_sharing.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # File upload configuration
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    KEY_FOLDER = os.path.join(BASE_DIR, 'keys')
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024 * 1024  # 2GB max file size

    # Allowed file extensions
    ALLOWED_EXTENSIONS = {
        # Documents
        'txt', 'pdf', 'doc', 'docx', 'odt', 'rtf', 'epub', 'md',
        # Spreadsheets
        'xls', 'xlsx', 'ods', 'csv', 'tsv',
        # Presentations
        'ppt', 'pptx', 'odp',
        # Images
        'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'svg', 'tiff', 'tif', 'ico', 'raw', 'psd', 'ai',
        # Audio
        'mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a', 'wma', 'opus',
        # Video
        'mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm', 'm4v', '3gp',
        # Archives
        'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'zst',
        # Code
        'py', 'java', 'cpp', 'c', 'h', 'cs', 'js', 'ts', 'jsx', 'tsx',
        'php', 'rb', 'go', 'rs', 'swift', 'kt', 'sh', 'bat', 'ps1',
        'html', 'css', 'scss', 'sass', 'sql', 'r', 'dart', 'lua',
        # Data / Config
        'json', 'xml', 'yaml', 'yml', 'toml', 'ini', 'cfg', 'env', 'log',
        # Fonts
        'ttf', 'otf', 'woff', 'woff2',
        # Executables / Packages (optional)
        'apk', 'exe', 'dmg', 'deb', 'rpm', 'iso',
    }

    # AES Encryption settings
    # Master key is used to encrypt/decrypt per-file keys
    # In production, this should be stored in a secure vault or HSM
    MASTER_KEY = os.environ.get('MASTER_KEY', 'ThisIsASecureMasterKeyForAES256Enc!')[:32]

    # Session configuration
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour session
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # Password hashing
    BCRYPT_LOG_ROUNDS = 12
