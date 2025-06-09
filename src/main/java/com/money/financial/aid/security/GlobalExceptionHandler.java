package com.money.financial.aid.security;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.stream.Collectors;

/**
 * Global handler for REST API exceptions.
 * Returns meaningful, non-leaky error responses to the client.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Handles validation errors (e.g., @Valid fails).
     * Returns BAD_REQUEST with a summary of validation failures.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ProblemDetail> onValidation(MethodArgumentNotValidException ex) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        pd.setTitle("Validation Failed");
        pd.setDetail(ex.getBindingResult().getFieldErrors().stream()
                .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
                .collect(Collectors.joining(", "))
        );
        return ResponseEntity.badRequest().body(pd);
    }

    /**
     * Handles all other uncaught exceptions.
     * Returns INTERNAL_SERVER_ERROR with only a message, never a stack trace.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> onAny(Exception ex) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.INTERNAL_SERVER_ERROR);
        pd.setTitle("Internal Error");
        pd.setDetail(ex.getMessage());
        return ResponseEntity.status(pd.getStatus()).body(pd);
    }
}
