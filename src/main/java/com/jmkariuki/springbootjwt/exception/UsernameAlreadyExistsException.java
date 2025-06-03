package com.jmkariuki.springbootjwt.exception;

public class UsernameAlreadyExistsException extends RuntimeException {

  public UsernameAlreadyExistsException(String message) {
    super(message);
  }
}
