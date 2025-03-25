"""Implements the FileStorage class for storing data in a file."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Literal, overload

from dataclasses import dataclass

import os
import time
from typing import Dict, TextIO, Tuple
from base64 import b64decode, b64encode

from openvector_cofhe_coprocessor_backend.common.lru_cache import LRUCache

class StorageError(Exception):
    """The StorageError class is a custom exception class that is raised when an exception
    occurs in the storage provider.
    """

    def __init__(self, message: str) -> None:
        """The constructor for the StorageError class.

        Args:
            message: The message to display when the exception is raised.
        """
        super().__init__(message)


class DecodingError(StorageError):
    """Raised when decoding the value from the file fails."""

    pass


@dataclass
class StoragePutOperationConfig:
    """The StoragePutOperationConfig class is a data class that defines the configuration
    for the put operation in the storage provider. The class defines the
    following attributes:
    - get_op_latency: The required latency for the get operation in the storage provider for the
        key to be put.
    - put_op_latency: The required latency for the put operation in the storage provider.
    - durability: The durability of the put operation in the storage provider.
    """

    get_op_latency: Literal["low", "medium", "high"] | int = "low"
    put_op_latency: Literal["low", "medium", "high"] | int = "low"
    durability: Literal["durable", "non-durable"] = "durable"


class Storage(ABC):
    """The storage interface class is an abstract class that defines the methods that
    any storage provider class must implement. Mainly the interface defines the following
    methods:
    - get -> This method should return the value stored in the storage
    provider for the given key.
    - put -> This method should store the value in the storage provider for the
    given key.
    - remove -> This method should remove the value stored in the storage provider
    for the given key.
    - update -> This method should update the value stored in the storage provider
    for the given key.
    - commit -> This method should commit the changes to the storage provider. Must
    be called before closing the storage provider.

    All the functions should accept key and value of different types like string, bytes, etc.
    The storage provider can be a file system, database, cache, etc. Also, the storage
    provider can be a local storage or a remote storage.
    """

    __slots__ = ()

    @overload
    def check(self, key: bytes) -> bool: ...
    @overload
    def check(self, key: str) -> bool: ...
    def check(self, key: str | bytes) -> bool:
        """This method should check if the key exists in the storage provider.

        Args:
            key: The key to check in the storage provider.

        Returns:
            True if the key exists in the storage provider, False otherwise.

        Raises:
            UnicodeEncodeError: If the key stored in the storage provider is not a valid
            unicode string.
            UnicodeDecodeError: If the value stored in the storage provider is not a valid
            unicode string.
            Any other exception: If any other exception occurs while getting the value from the
            storage provider.
        """
        try:
            self.get(key)
            return True
        except KeyError:
            return False

    @overload
    def get(self, key: bytes) -> bytes: ...
    @overload
    def get(self, key: str) -> str: ...
    def get(self, key: str | bytes) -> str | bytes:
        """This method should return the value stored in the storage provider for the given key.

        Allows to store str-str and bytes-bytes key-value pairs.

        Args:
            key: The key to get the value from the storage provider.

        Returns:
            The value stored in the storage provider for the given key.

        Raises:
            KeyError: If the key is not found in the storage provider.
            UnicodeEncodeError: If the key stored in the storage provider is not a valid
            unicode string.
            UnicodeDecodeError: If the value stored in the storage provider is not a valid
            unicode string.
            Any other exception: If any other exception occurs while getting the value from the
            storage provider.
        """
        if isinstance(key, str):
            return (self._get(key.encode())).decode()
        return self._get(key)

    @abstractmethod
    def _get(self, key: bytes) -> bytes:
        """This method actually implements the get operation in the storage provider.

        The actual implementation of the method should be done by the concrete class that
        implements the Storage interface. The method should raise a KeyError if the key is not
        found in the storage provider.

        Args:
            key: The key to get the value from the storage provider.

        Returns:
            The value stored in the storage provider for the given key.

        Raises:
            KeyError: If the key is not found in the storage provider.
            Any other exception: If any other exception occurs while getting the value from the
            storage provider.
        """
        pass

    @overload
    def put(
        self,
        key: bytes,
        value: bytes,
        config: StoragePutOperationConfig = StoragePutOperationConfig(),
    ) -> None: ...
    @overload
    def put(
        self,
        key: str,
        value: str,
        config: StoragePutOperationConfig = StoragePutOperationConfig(),
    ) -> None: ...
    def put(
        self,
        key: str | bytes,
        value: str | bytes,
        config: StoragePutOperationConfig = StoragePutOperationConfig(),
    ) -> None:
        """This method should store the value in the storage provider for the given key.

        Allows to store str-str and bytes-bytes key-value pairs.

        Args:
            key: The key to store the value in the storage provider.
            value: The value to store in the storage provider for the given key.
            config: The configuration for the put operation in the storage provider.

        Returns:
            None

        Raises:
            KeyError: If the key is already present in the storage provider.
            ValueError: If the key-value pair is not of str-str or bytes-bytes type.
            UnicodeEncodeError: If the key stored in the storage provider is not a valid
            unicode string.
            UnicodeDecodeError: If the value stored in the storage provider is not a valid
            unicode string.
            Any exception: If any exception occurs while storing the value in the storage provider.
        """
        if isinstance(key, str):
            if isinstance(value, str):
                return self._put(key.encode(), value.encode(), config)
            raise ValueError("Value should be of type str")
        else:
            if isinstance(value, bytes):
                return self._put(key, value, config)
            raise ValueError("Value should be of type bytes")

    @abstractmethod
    def _put(
        self, key: bytes, value: bytes, config: StoragePutOperationConfig
    ) -> None:
        """This method actually implements the put operation in the storage provider.

        The actual implementation of the method should be done by the concrete class that
        implements the Storage interface. This method should raise an KeyError if the key is
        already present in the storage provider.

        Args:
            key: The key to store the value in the storage provider.
            value: The value to store in the storage provider for the given key.
            config: The configuration for the put operation in the storage provider.

        Returns:
            None

        Raises:
            KeyError: If the key is already present in the storage provider.
            Any exception: If any exception occurs while storing the value in the storage provider.
        """
        pass

    @overload
    def remove(self, key: bytes) -> None: ...
    @overload
    def remove(self, key: str) -> None: ...
    def remove(self, key: str | bytes) -> None:
        """This method should remove the value stored in the storage provider for the given key.

        Args:
            key: The key to remove the value from the storage provider.

        Returns:
            None

        Raises:
            KeyError: If the key is not found in the storage provider.
            UnicodeEncodeError: If the key stored in the storage provider is not a valid
            unicode string.
            Any other exception: If any other exception occurs while removing the value from the
            storage provider.
        """
        if isinstance(key, str):
            return self._remove(key.encode())
        else:
            return self._remove(key)

    @abstractmethod
    def _remove(self, key: bytes) -> None:
        """This method actually implements the remove operation in the storage provider.

        The actual implementation of the method should be done by the concrete class that
        implements the Storage interface. The method should raise a KeyError if the key is not
        found in the storage provider.

        Args:
            key: The key to remove the value from the storage provider.

        Returns:
            None

        Raises:
            KeyError: If the key is not found in the storage provider.
            Any other exception: If any other exception occurs while removing the value from the
            storage provider.
        """
        pass

    @overload
    def update(self, key: bytes, value: bytes) -> None: ...
    @overload
    def update(self, key: str, value: str) -> None: ...
    def update(self, key: str | bytes, value: str | bytes) -> None:
        """This method should update the value stored in the storage provider for the given key.

        Args:
            key: The key to update the value in the storage provider.
            value: The value to update in the storage provider for the given key.

        Returns:
            None

        Raises:
            KeyError: If the key is not found in the storage provider.
            ValueError: If the key-value pair is not of str-str or bytes-bytes type.
            UnicodeEncodeError: If the key stored in the storage provider is not a valid
            unicode string.
            UnicodeDecodeError: If the value stored in the storage provider is not a valid
            unicode string.
            Any other exception: If any other exception occurs while updating the value in the
            storage provider.
        """
        if isinstance(key, str):
            if isinstance(value, str):
                return self._update(key.encode(), value.encode())
            raise ValueError("Value should be of type str")
        else:
            if isinstance(value, bytes):
                return self._update(key, value)
            raise ValueError("Value should be of type bytes")

    @abstractmethod
    def _update(self, key: bytes, value: bytes) -> None:
        """This method actually implements the update operation in the storage provider.

        The actual implementation of the method should be done by the concrete class that
        implements the Storage interface. The method should raise a KeyError if the key is not
        found in the storage provider.

        Args:
            key: The key to update the value in the storage provider.
            value: The value to update in the storage provider for the given key.

        Returns:
            None

        Raises:
            KeyError: If the key is not found in the storage provider.
            Any other exception: If any other exception occurs while updating the value in the
            storage provider.
        """
        pass

    def commit(self) -> None:
        """This method should commit the changes to the storage provider.
        Returns:
            None

        Raises:
            Any exception: If any exception occurs while committing the changes to the storage provider.
        """
        self._commit()
    @abstractmethod
    def _commit(self) -> None:
        """This method actually implements the commit operation in the storage provider.

        The actual implementation of the method should be done by the concrete class that
        implements the Storage interface.

        Returns:
            None

        Raises:
            Any exception: If any exception occurs while committing the changes to the storage provider.
        """
        pass


class FileStorage(Storage):
    """The FileStorage class is a concrete class that implements the Storage interface for
    file storage.

    The file is opened in read mode to read the data from the file. When any write operation(put,
    update, remove) is called, the file is opened in write mode and the data is written to the file.

    In normal operation, the data is only appended to the file. This means that even for a remove
    operation, the data is not removed from the file. Just the key is inserted again with a None
    value. And for an update operation, the data is inserted again with the new value. This is done
    to keep the implementation simple and to avoid the overhead of writing the entire file again.

    When the file size exceeds defined size, then the data is cleaned for the keys that have None value or
    not the latest value. This is done to keep the file size in check and to avoid the file size
    from growing indefinitely. When performing this operation, a copy of the file is created and the
    data is written to the new file. Once the data is written to the new file, the old file is deleted
    and the new file is renamed to the old file. This is done to avoid any data loss in case of any
    failure during the operation. Similiar temp copy and rename is followed for metadata file.

    Keeps recently accessed keys and parts of file in memory to avoid reading the file for every get operation.

    The data is encoded as base64 before writing to the file and decoded as base64 after reading from the file.
    Each key-value is stored in a separate line in the file. Key and value are separated by a ":".

    There are 2 sections in the file:
    1. Data section: Contains the actual key-value pairs. These are in sorted order.
    2. Log section: Contains the logs of the operations performed on the file. These are the operations
        that are not yet written to the file.

    The metadata is stored in a separate file named <file_path>.meta. The metadata contains the following:
    - last_updated: The timestamp when the metadata was last updated.
    - max_file_size: The maximum size of the file in bytes.
    - log_ratio: The ratio of junk data to keep in the file.
    - start_line_log: The line number where the data section  starts.
    - prefetch_size: The number of keys to keep in memory.
    - the top prefetch_size keys accessed recently.

    All these are stored on separate lines. The recent keys are stored as a comma-separated list on the last line.

    Spatial buffer size is used to keep the recently accessed keys in memory. The spatial buffer size is
    calculated as prefetch_size/10 + 5.
    """

    __slots__ = (
        "_file_path",
        "_file",
        "_buffer",
        "_dirty_buffer",
        "_recent_keys",
        "_last_updated",
        "_max_file_size",
        "_log_ratio",
        "_start_line_log",
        "_prefetch_size",
        "_spatial_buffer_size",
    )

    _file_path: str
    _file: TextIO
    _buffer: LRUCache[str, str]
    _dirty_buffer: Dict[str, str | None]
    _recent_keys: LRUCache[str, int]
    _last_updated: int
    _max_file_size: int
    _log_ratio: float
    _start_line_log: int
    _prefetch_size: int
    _spatial_buffer_size: int

    def __init__(self, file_path: str) -> None:
        """The constructor for the FileStorage class.

        Args:
            file_path: The path to the file where the data will be stored.
        """
        self._file_path = file_path
        if not os.path.exists(file_path):
            raise StorageError("File does not exist")
        self._file = open(file_path, "a+", encoding="utf-8")
        self._buffer = LRUCache(0)
        self._dirty_buffer = {}
        self._recent_keys = LRUCache(0)

        self._last_updated = int(time.time())
        self._max_file_size = 1000
        self._log_ratio = 0.3
        self._start_line_log = 1
        self._prefetch_size = 10
        self._spatial_buffer_size = self._prefetch_size // 10 + 5

        self._load_data()

    # def __del__(self) -> None:
    #     """The destructor for the FileStorage class.

    #     It writes the dirty buffer to the file before closing the file.

    #     The destructor also closes the file when the object is deleted.
    #     """
    #     # to make sure that we only try to commit if the file is open
    #     # ie the constructor was 
    #     if object.__getattribute__(self, "_file"):
    #         self._do_commit()

    def _load_data(self) -> None:
        """This method loads the data from the file to the buffer.

        The method reads the file line by line and loads the data to the buffer.
        Currently, we load the entire file to the buffer.
        """
        # read the metadata
        try:
            with open(self._file_path + ".meta", "r", encoding="utf-8") as meta_file:
                metadata = meta_file.readlines()
                if len(metadata) != 6:
                    raise StorageError("Invalid metadata")
                last_updated = metadata[0]
                max_file_size = int(metadata[1])
                log_ratio = float(metadata[2])
                start_line_log = int(metadata[3])
                prefetch_size = int(metadata[4])
                # currently we dont use the keys
                # but if the data is very large and sorted then it will be useful
                keys = metadata[5].strip().split(",")

                self._last_updated = int(last_updated)
                self._max_file_size = max_file_size
                self._log_ratio = log_ratio
                self._start_line_log = start_line_log
                self._prefetch_size = prefetch_size
                self._spatial_buffer_size = int(prefetch_size / 10) + 5

                self._recent_keys = LRUCache(prefetch_size)

                # no recent keys
                if keys == [""]:
                    keys = []
                for key in keys:
                    self._recent_keys[key] = 0

                self._buffer = LRUCache(prefetch_size)
                self._dirty_buffer = {}
        except Exception as e:
            raise StorageError("Error loading metadata") from e

        self._file.seek(0)
        current_line = 0
        # read the data section
        while (
            len(self._buffer) < self._prefetch_size
            and current_line < self._start_line_log
        ):
            line = self._file.readline().strip()
            if line == "" or current_line >= start_line_log:
                break
            if ":" not in line:
                raise StorageError("Invalid data in the file")
            key, value = line.split(":")
            if value == "":
                raise StorageError("Invalid data in the file")
            self._buffer[key] = value

            current_line += 1

        # read the log section
        # we dont consider the prefetch size for the log section
        while True:
            line = self._file.readline().strip()
            if line == "":
                break
            if ":" not in line:
                raise StorageError("Invalid data in the file")
            key, value = line.split(":")
            # No need to keep the same key in the buffer and dirty buffer
            # just keep the latest value
            if key in self._buffer:
                self._buffer.pop(key)
            if value == "":
                if key in self._dirty_buffer:
                    self._dirty_buffer.pop(key)
            else:
                self._dirty_buffer[key] = value
            current_line += 1

    def _do_commit(self) -> None:
        """The destructor for the FileStorage class.

        It writes the dirty buffer to the file before closing the file.

        It also closes the file.
        """
        # read all the items in data section
        self._file.seek(0)
        current_line = 0
        data: Dict[str, str] = {}
        while current_line < self._start_line_log:
            line = self._file.readline().strip()
            if line == "":
                break
            if ":" not in line:
                raise StorageError("Invalid data in the file")
            key, value = line.split(":")
            if value == "":
                raise StorageError("Invalid data in the file")
            data[key] = value
            current_line += 1

        # merge the buffer and dirty buffer
        for key, dirty_value in self._dirty_buffer.items():
            if dirty_value is None:
                data[key] = ""
            else:
                data[key] = dirty_value

        # sort the data
        data = dict(sorted(data.items()))
        # write the data section
        # no need to write the log section as it is already written
        start_line_log = 0
        with open(self._file_path + ".tmp", "w", encoding="utf-8") as tmp_file:
            for key, value in data.items():
                if value != "":
                    tmp_file.write(f"{key}:{value}\n")
                    start_line_log += 1

        # write the data to the temp file
        # write the metadata
        with open(self._file_path + ".meta.tmp", "w", encoding="utf-8") as meta_file:
            meta_file.write(
                f"{int(time.time())}\n{self._max_file_size}\n{self._log_ratio}\n{start_line_log}\n{self._prefetch_size}\n"
            )
            meta_file.write(",".join(self._recent_keys.keys()))
            meta_file.write("\n")

        # close the original file
        self._file.close()

        # rename the temp file to the original file
        os.rename(self._file_path + ".meta.tmp", self._file_path + ".meta")
        os.rename(self._file_path + ".tmp", self._file_path)

    def _increase_log_size(self) -> None:
        """Increase the log size in the file."""

    def _get(self, key: bytes) -> bytes:
        """Implements the get operation in the file storage.

        Raises:
            KeyError: If the key is not found in the file.
            DecodingError: If the value stored in the file is not a valid unicode string.
        """
        b64_key = b64encode(key).decode("ascii")
        if b64_key in self._dirty_buffer:
            try:
                value = self._dirty_buffer[b64_key]
                if value is None:
                    raise KeyError("Key not found")
                self._recent_keys[b64_key] = self._recent_keys.get(b64_key, 0) + 1  # type: ignore
                return b64decode(value)
            except Exception as e:
                if isinstance(e, KeyError):
                    raise e
                raise DecodingError("Error decoding the value") from e
        if b64_key in self._buffer:
            try:
                self._recent_keys[b64_key] = self._recent_keys.get(b64_key, 0) + 1  # type: ignore
                return b64decode(self._buffer[b64_key])
            except Exception as e:
                raise DecodingError("Error decoding the value") from e

        spatial_buffer: LRUCache[str, Tuple[str, int]] = LRUCache(
            self._spatial_buffer_size
        )
        # read the file
        self._file.seek(0)
        current_line = 0
        while current_line < self._start_line_log:
            line = self._file.readline().strip()
            if line == "":
                break
            if ":" not in line:
                raise StorageError("Invalid data in the file")
            k, v = line.split(":")
            if v == "":
                raise StorageError("Invalid data in the file")
            spatial_buffer[k] = (v, current_line)
            if k == b64_key:
                try:
                    for k, v_l in spatial_buffer.items():
                        self._buffer[k] = v_l
                    self._recent_keys[b64_key] = self._recent_keys.get(b64_key, 0) + 1  # type: ignore
                    return b64decode(v)
                except Exception as e:
                    raise DecodingError("Error decoding the value") from e
            current_line += 1
        # Do not check the log section for the key as it is already checked in the dirty buffer
        raise KeyError("Key not found")

    def _put(
        self, key: bytes, value: bytes, config: StoragePutOperationConfig
    ) -> None:
        """Implements the put operation in the file storage."""
        b64_key = b64encode(key).decode("ascii")
        b64_value = b64encode(value).decode("ascii")

        if b64_key in self._buffer or (b64_key in self._dirty_buffer and self._dirty_buffer[b64_key] is not None):
            raise KeyError("Key already present")

        self._dirty_buffer[b64_key] = b64_value

        # seek to the end of the file
        self._file.seek(0, 2)
        self._file.write(f"{b64_key}:{b64_value}\n")
        self._file.flush()

    def _remove(self, key: bytes) -> None:
        """Implements the remove operation in the file storage."""
        b64_key = b64encode(key).decode("ascii")
        self._dirty_buffer[b64_key] = None
        if b64_key in self._buffer:
            self._buffer.pop(b64_key)

        # seek to the end of the file
        self._file.seek(0, 2)
        self._file.write(f"{b64_key}:\n")
        self._file.flush()

    def _update(self, key: bytes, value: bytes) -> None:
        """Implements the update operation in the file storage."""
        b64_key = b64encode(key).decode("ascii")
        b64_value = b64encode(value).decode("ascii")

        #check if the key is actually present in the file
        if b64_key not in self._buffer and (b64_key not in self._dirty_buffer or self._dirty_buffer[b64_key] is None):
            raise KeyError("Key not found")
        
        self._dirty_buffer[b64_key] = b64_value
        if b64_key in self._buffer:
            self._buffer.pop(b64_key)

        # seek to the end of the file
        self._file.seek(0, 2)
        self._file.write(f"{b64_key}:{b64_value}\n")
        self._file.flush()

    def _commit(self) -> None:
        """Commits the changes to the file."""
        self._do_commit()
        if not os.path.exists(self._file_path):
            raise StorageError("File does not exist")
        self._file = open(self._file_path, "a+", encoding="utf-8")
        self._load_data()

    @classmethod
    def create(
        cls,
        file_path: str,
        max_file_size: int = 1000,
        log_ratio: float = 0.3,
        prefetch_size: int = 100,
        overwrite: bool = False,
    ) -> FileStorage:
        """Create a new FileStorage object with the given parameters."""
        if not overwrite and (
            os.path.exists(file_path) or os.path.exists(file_path + ".meta")
        ):
            raise StorageError("File already exists")
        with open(f"{file_path}.meta", "w", encoding="utf-8") as file:
            file.write(
                f"{int(time.time())}\n{max_file_size}\n{log_ratio}\n{0}\n{prefetch_size}\n\n"
            )
        with open(file_path, "w", encoding="utf-8") as file:
            file.write("")
        return FileStorage(file_path)