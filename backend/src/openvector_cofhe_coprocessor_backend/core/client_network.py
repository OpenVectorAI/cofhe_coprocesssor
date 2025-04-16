from __future__ import annotations

from abc import ABC, abstractmethod

from openvector_cofhe_coprocessor_backend.core.request_response import Request, Response, ConfidentialCoinRequest, ConfidentialCoinResponse


class IClientNetwork(ABC):
    __slots__ =("_id",)

    _id: str

    def __init__(self, id: str):
        self._id = id

    @property
    def id(self) -> str:
        return self._id

    @abstractmethod
    def run(self) -> None:
        """Called by the main loop to run the client network such as ethereum

        This method must be non-blocking and should return immediately, spin up a new thread if needed
        """
        pass

    @abstractmethod
    def stop(self) -> None:
        """Called by the main loop to stop the client network"""
        pass

    @abstractmethod
    def request_available(self) -> bool:
        """Called by the main loop to check if there is any request available from the client network such as ethereum

        Must return immediately
        """
        pass

    @abstractmethod
    def get_request(self) -> Request|ConfidentialCoinRequest:
        """Called by the main loop to get the request from the client network such as ethereum to process

        Must only return the request that are valid and can be processed, the main processing service wont
        check the validity of the request for things related to the client network such as fees, etc
        """
        pass

    @abstractmethod
    def put_response(self, response: Response|ConfidentialCoinResponse) -> None:
        """Called by the main loop to put the response back to the client network such as ethereum

        Called for both acceptance and completion of the request
        """
        pass
