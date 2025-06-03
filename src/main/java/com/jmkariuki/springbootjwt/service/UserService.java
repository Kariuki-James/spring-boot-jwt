package com.jmkariuki.springbootjwt.service;

import com.jmkariuki.springbootjwt.dto.AuthRegistrationRequest;
import com.jmkariuki.springbootjwt.exception.UsernameAlreadyExistsException;
import com.jmkariuki.springbootjwt.model.User;
import com.jmkariuki.springbootjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;

  @Autowired
  public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
    this.userRepository = userRepository;
    this.passwordEncoder = passwordEncoder;
  }

  public void registerUser(AuthRegistrationRequest request) {
    if (userRepository.existsByUsername(request.username())) {
      throw new UsernameAlreadyExistsException("Username already exists");
    }

    User user = new User();
    user.setUsername(request.username());
    user.setPassword(passwordEncoder.encode(request.password()));
    user.setEnabled(true);
    user.addAuthority("ROLE_USER");

    userRepository.save(user);
  }
}
