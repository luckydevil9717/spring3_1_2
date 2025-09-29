package ru.kata.spring.boot_security.demo.service;





import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.model.User;

import java.util.List;

public interface UserService {
    List<User> getAllUsers();
    void saveUser(User user);
    User getUser(Long id);
    void deleteUser(Long id);
    void saveUserWithRoles(User user, Long[] roleIds);
    void updateUserWithRoles(User user, Long[] roleIds);
    List<Role> getAllRoles();

    boolean existsByEmail(String email);
    boolean existsByEmailExceptId(String email, Long id);
}
