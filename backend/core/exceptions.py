from fastapi import HTTPException, status


class ProviderNotFoundError(HTTPException):
    def __init__(self, provider: str):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"LLM provider '{provider}' is not registered.",
        )


class ProviderAuthError(HTTPException):
    def __init__(self, provider: str):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Missing or invalid API key for provider '{provider}'.",
        )


class AttackNotFoundError(HTTPException):
    def __init__(self, attack_id: int):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack with id={attack_id} not found.",
        )


class EvaluationNotFoundError(HTTPException):
    def __init__(self, run_id: int):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evaluation run with id={run_id} not found.",
        )


class PipelineError(Exception):
    def __init__(self, stage: str, message: str):
        self.stage = stage
        self.message = message
        super().__init__(f"Pipeline failed at stage '{stage}': {message}")
