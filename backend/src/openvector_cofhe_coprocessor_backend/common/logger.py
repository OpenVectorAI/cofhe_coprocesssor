"""Implments the Logger interface and the LogMessage and StructuredLogMessage dataclasses and StandardLogger class."""

from __future__ import annotations


import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
import datetime as dt
import json
import logging
import logging.config
from typing import overload


class LogLevel(Enum):
    """Enum for log levels. The lower the value, the more verbose the log message."""

    TRACE = -1
    """Trace log level. Should be used for development purposes only."""
    DEBUG = 0
    """Debug log level. Again, mostly for development purposes."""
    INFO = 1
    """Info log level. Should be used for general information."""
    WARNING = 2
    """Warning log level. Should be used for non-critical issues."""
    ERROR = 3
    """Error log level. Should be used for errors that can be recovered from."""
    CRITICAL = 4
    """Critical log level. Should be used for errors that cannot be recovered from."""
    FATAL = 5
    """Fatal log level. Should be used for errors that cause the program to exit."""


@dataclass(slots=True)
class LogMessage:
    """Dataclass for log messages.

    Attributes:
        message:
            The message to log.
        level:
            The log level. Defaults to LogLevel.INFO. And if a specific log function(like log_error) is called,
            then level will be ignored.
        structured_log_message_data:
            Structured log data. Defaults to an empty dictionary.
        error:
            The exception that caused the error. Defaults to None.
        stacklevel:
            The stack frame to log. Defaults to 1.
    """

    message: str
    level: LogLevel = LogLevel.INFO
    structured_log_message_data: dict[str, str] = field(default_factory=dict)
    error: Exception | None = None
    stacklevel: int = 1


class LoggingError(Exception):
    """Raised when an error occurs during logging."""

    pass


class Logger(ABC):
    """Abstract base class for loggers"""

    __slots__ = ("_min_level",)
    _min_level: LogLevel

    def __init__(self, min_level: LogLevel = LogLevel.WARNING):
        self._min_level = min_level

    @overload
    def log(self, message: str) -> None: ...
    @overload
    def log(self, message: LogMessage) -> None: ...
    def log(self, message: str | LogMessage) -> None:
        """Log a message.

        Args:
            message: The message to log.

        Raises:
            ValueError: If the log level is invalid.
            LoggingError: If an error occurs during logging.
        """
        if isinstance(message, str):
            message = LogMessage(message=message, level=self._min_level)

        if message.level.value < self._min_level.value:
            return
        if message.level == LogLevel.TRACE:
            self.trace(message)
        elif message.level == LogLevel.INFO:
            self.info(message)
        elif message.level == LogLevel.DEBUG:
            self.debug(message)
        elif message.level == LogLevel.WARNING:
            self.warning(message)
        elif message.level == LogLevel.ERROR:
            self.error(message)
        elif message.level == LogLevel.CRITICAL:
            self.critical(message)
        elif message.level == LogLevel.FATAL:
            self.fatal(message)
        else:
            raise ValueError(f"Invalid log level: {message.level}")

    @overload
    def trace(self, message: str) -> None: ...
    @overload
    def trace(self, message: LogMessage) -> None: ...
    def trace(self, message: str | LogMessage) -> None:
        """Log a trace message.

        Args:
            message: The message to log.

        Raises:
            LoggingError: If an error occurs during logging
        """
        if isinstance(message, str):
            message = LogMessage(message=message, level=self._min_level)
        message.level = LogLevel.TRACE
        message.stacklevel += 1
        message.structured_log_message_data["log_level"] = "TRACE"
        self._trace(message)

    @abstractmethod
    def _trace(self, message: LogMessage) -> None:
        """Log a trace message.

        Args:
            message: The message to log.

        Raises:
            LoggingError: If an error occurs during logging
        """
        pass
    
    @overload
    def info(self, message: str) -> None: ...
    @overload
    def info(self, message: LogMessage) -> None: ...
    def info(self, message: str | LogMessage) -> None:
        """Log an info message.

        Args:
            message: The message to log.
        Raises:
            LoggingError: If an error occurs during logging
        """
        if isinstance(message, str):
            message = LogMessage(message=message, level=self._min_level)
        message.level = LogLevel.INFO
        message.stacklevel += 1
        message.structured_log_message_data["log_level"] = "INFO"
        self._info(message)

    @abstractmethod
    def _info(self, message: LogMessage) -> None:
        """Log an info message.

        Args:
            message: The message to log.
        Raises:
            LoggingError: If an error occurs during logging
        """
        pass
    
    @overload
    def debug(self, message: str) -> None: ...
    @overload
    def debug(self, message: LogMessage) -> None: ...
    def debug(self, message: str | LogMessage) -> None:
        """Log a debug message.

        Args:
            message: The message to log.

        Raises:
            LoggingError: If an error occurs during logging
        """
        if isinstance(message, str):
            message = LogMessage(message=message, level=self._min_level)
        message.level = LogLevel.DEBUG
        message.stacklevel += 1
        message.structured_log_message_data["log_level"] = "DEBUG"
        self._debug(message)

    @abstractmethod
    def _debug(self, message: LogMessage) -> None:
        """Log a debug message.

        Args:
            message: The message to log.

        Raises:
            LoggingError: If an error occurs during logging
        """
        pass
    
    @overload
    def warning(self, message: str) -> None: ...
    @overload
    def warning(self, message: LogMessage) -> None: ...
    def warning(self, message: str | LogMessage) -> None:
        """Log a warning message.

        Args:
            message: The message to log.

        Raises:
            LoggingError: If an error occurs during logging
        """
        if isinstance(message, str):
            message = LogMessage(message=message, level=self._min_level)
        message.level = LogLevel.WARNING
        message.stacklevel += 1
        message.structured_log_message_data["log_level"] = "WARNING"
        self._warning(message)

    @abstractmethod
    def _warning(self, message: LogMessage) -> None:
        """Log a warning message.

        Args:
            message: The message to log.

        Raises:
            LoggingError: If an error occurs during logging
        """
        pass
    
    @overload
    def error(self, message: str) -> None: ...
    @overload
    def error(self, message: LogMessage) -> None: ...
    def error(self, message: str | LogMessage) -> None:
        """Log an error message.

        Args:
            message: The message to log.

        Raises:
            LoggingError: If an error occurs during logging
        """
        if isinstance(message, str):
            message = LogMessage(message=message, level=self._min_level)
        message.level = LogLevel.ERROR
        message.stacklevel += 1
        message.structured_log_message_data["log_level"] = "ERROR"
        self._error(message)

    @abstractmethod
    def _error(self, message: LogMessage) -> None:
        """Log an error message.

        Args:
            message: The message to log.

        Raises:
            LoggingError: If an error occurs during logging
        """
        pass
    
    @overload
    def critical(self, message: str) -> None: ...
    @overload
    def critical(self, message: LogMessage) -> None: ...
    def critical(self, message: str | LogMessage) -> None:
        """Log a critical message.

        Args:
            message: The message to log.

        Raises:
            LoggingError: If an error occurs during logging
        """
        if isinstance(message, str):
            message = LogMessage(message=message, level=self._min_level)
        message.level = LogLevel.CRITICAL
        message.stacklevel += 1
        message.structured_log_message_data["log_level"] = "CRITICAL"
        self._critical(message)

    @abstractmethod
    def _critical(self, message: LogMessage) -> None:
        """Log a critical message.

        Args:
            message: The message to log.

        Raises:
            LoggingError: If an error occurs during logging
        """
        pass

    @overload
    def fatal(self, message: str) -> None: ...
    @overload
    def fatal(self, message: LogMessage) -> None: ...
    def fatal(self, message: str | LogMessage) -> None:
        """Log a fatal message.

        Args:
            message: The message to log.

        Raises:
            LoggingError: If an error occurs during logging
        """
        if isinstance(message, str):
            message = LogMessage(message=message, level=self._min_level)
        message.level = LogLevel.FATAL
        message.stacklevel += 1
        message.structured_log_message_data["log_level"] = "FATAL"
        exit_code = message.structured_log_message_data.get("exit_code", 1)
        self._fatal(message)
        sys.exit(exit_code) if isinstance(exit_code, int) else sys.exit(1)

    def _fatal(self, message: LogMessage) -> None:
        """Log a fatal message.

        Args:
            message: The message to log.

        Raises:
            LoggingError: If an error occurs during logging
        """
        pass


LOG_RECORD_BUILTIN_ATTRS = {
    "args",
    "asctime",
    "created",
    "exc_info",
    "exc_text",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "module",
    "msecs",
    "message",
    "msg",
    "name",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "thread",
    "threadName",
    "taskName",
}


class MyJSONFormatter(logging.Formatter):
    """Custom JSON formatter for logging."""

    def __init__(
        self,
        *,
        fmt_keys: dict[str, str] | None = None,
    ):
        super().__init__()
        self.fmt_keys = fmt_keys if fmt_keys is not None else {}

    def format(self, record: logging.LogRecord) -> str:
        message = self._prepare_log_dict(record)
        return json.dumps(message, default=str)

    def _prepare_log_dict(self, record: logging.LogRecord):
        always_fields = {
            "message": record.getMessage(),
            "timestamp": dt.datetime.fromtimestamp(
                record.created, tz=dt.timezone.utc
            ).isoformat(),
        }
        if record.exc_info is not None:
            always_fields["exc_info"] = self.formatException(record.exc_info)

        if record.stack_info is not None:
            always_fields["stack_info"] = self.formatStack(record.stack_info)

        message = {
            key: (
                msg_val
                if (msg_val := always_fields.pop(val, None)) is not None
                else getattr(record, val)
            )
            for key, val in self.fmt_keys.items()
        }
        message.update(always_fields)

        for key, val in record.__dict__.items():
            if key not in LOG_RECORD_BUILTIN_ATTRS:
                message[key] = val

        return message


class StandardLogger(Logger):
    """Standard logger that logs to the console."""

    __slots__ = ("_logger",)

    def __init__(
        self,
        config_path: str,
    ):
        """Initialize the logger.

        Args:
            config_path:
                The path to the logger configuration file. Must be in json format.

        Raises:
            FileNotFoundError: If the config file is not found.
            JsonDecodeError: If the config file is not in json format.
        """
        min_logging_level = LogLevel.WARNING
        with open(config_path, "r", encoding="utf-8") as file:
            config = json.load(file)
            logging.config.dictConfig(config)
            min_logging_level = LogLevel(logging.getLogger().getEffectiveLevel() // 10)
        super().__init__(min_logging_level)

        self._logger = logging.getLogger("openvector_cofhe_coprocessor_backend_logger")

    def _trace(self, message: LogMessage) -> None:
        self._logger.log(
            0,
            message.message,
            extra=message.structured_log_message_data,
            stacklevel=message.stacklevel,
            exc_info=message.error,
        )

    def _info(self, message: LogMessage) -> None:
        self._logger.info(
            message.message,
            extra=message.structured_log_message_data,
            stacklevel=message.stacklevel,
            exc_info=message.error,
        )

    def _debug(self, message: LogMessage) -> None:
        self._logger.debug(
            message.message,
            extra=message.structured_log_message_data,
            stacklevel=message.stacklevel,
            exc_info=message.error,
        )

    def _warning(self, message: LogMessage) -> None:
        self._logger.warning(
            message.message,
            extra=message.structured_log_message_data,
            stacklevel=message.stacklevel,
            exc_info=message.error,
        )

    def _error(self, message: LogMessage) -> None:
        self._logger.error(
            message.message,
            extra=message.structured_log_message_data,
            stacklevel=message.stacklevel,
            exc_info=message.error,
        )

    def _critical(self, message: LogMessage) -> None:
        self._logger.critical(
            message.message,
            extra=message.structured_log_message_data,
            stacklevel=message.stacklevel,
            exc_info=message.error,
        )

    def _fatal(self, message: LogMessage) -> None:
        self._logger.fatal(
            message.message,
            extra=message.structured_log_message_data,
            stacklevel=message.stacklevel,
            exc_info=message.error,
        )
