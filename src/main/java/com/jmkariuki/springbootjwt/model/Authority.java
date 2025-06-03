package com.jmkariuki.springbootjwt.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

@Entity
@Table(name = "authorities", uniqueConstraints = {
    @UniqueConstraint(columnNames = {"username", "authority"})
})
public class Authority {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @ManyToOne
  @JoinColumn(name = "username", referencedColumnName = "username", nullable = false)
  private User user;

  @Column(length = 50, nullable = false)
  private String authority;

  public Authority() {
  }

  public Authority(User user, String authority) {
    this.user = user;
    this.authority = authority;
  }

  public Long getId() {
    return id;
  }

  public User getUser() {
    return user;
  }

  public String getAuthority() {
    return authority;
  }
}
