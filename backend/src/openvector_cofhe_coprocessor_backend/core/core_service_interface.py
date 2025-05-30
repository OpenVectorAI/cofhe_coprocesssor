from __future__ import annotations

from abc import ABC, abstractmethod

from openvector_cofhe_coprocessor_backend.common.request_response import (
    ConfidentialCoinRequest,
    ConfidentialCoinResponse,
    Request,
    Response,
)


class ICoreService(ABC):
    @abstractmethod
    def run(self) -> None:
        """Run the core service"""
        pass

    @abstractmethod
    def stop(self) -> None:
        """Stop the core service"""
        pass

    @abstractmethod
    def submit_request(self, request: Request | ConfidentialCoinRequest) -> str:
        """Process the request"""
        pass

    @abstractmethod
    def response_available(self) -> bool:
        """Check the response"""
        pass

    @abstractmethod
    def get_response(self) -> Response | ConfidentialCoinResponse:
        """Get the response"""
        pass
