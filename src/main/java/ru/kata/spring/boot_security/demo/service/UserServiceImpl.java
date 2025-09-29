package ru.kata.spring.boot_security.demo.service;

import org.springframework.stereotype.Service;
import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.repository.RoleRepository;
import ru.kata.spring.boot_security.demo.repository.UserRepository;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService {
    private final UserRepository userRepo;
    private final RoleRepository roleRepo;

    public UserServiceImpl(UserRepository userRepo, RoleRepository roleRepo) {
        this.userRepo = userRepo;
        this.roleRepo = roleRepo;
    }

    @Override
    public List<User> getAllUsers() {
        return userRepo.findAll();
    }

    @Override
    public void saveUser(User user) {
        userRepo.save(user);
    }

    @Override
    public User getUser(Long id) {
        return userRepo.findById(id).orElse(null);
    }

    @Override
    public void deleteUser(Long id) {
        userRepo.deleteById(id);
    }


    public void saveUserWithRoles(User user, Long[] roleIds) {
        Set<Role> roles = Arrays.stream(roleIds)
                .map(roleRepo::findById)
                .map(opt -> opt.orElseThrow(() -> new RuntimeException("Role not found")))
                .collect(Collectors.toSet());
        user.setRoles(roles);
        userRepo.save(user);
    }

    public void updateUserWithRoles(User user, Long[] roleIds) {
        saveUserWithRoles(user, roleIds);
    }

    public List<Role> getAllRoles() {
        return roleRepo.findAll();
    }
    @Override
    public boolean existsByEmail(String email) {
        return userRepo.countByEmail(email) > 0;
    }

    @Override
    public boolean existsByEmailExceptId(String email, Long id) {
        return userRepo.countByEmailAndIdNot(email, id) > 0;
    }

}