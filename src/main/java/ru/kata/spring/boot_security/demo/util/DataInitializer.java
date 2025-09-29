package ru.kata.spring.boot_security.demo.util;

import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.service.UserService;

import java.util.Set;

@Component
public class DataInitializer implements CommandLineRunner {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(UserService userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        // роли
        Role roleUser = new Role("ROLE_USER");
        Role roleAdmin = new Role("ROLE_ADMIN");

        // пользователи
        User user = new User("User", "User", 25, "user@mail.ru",
                passwordEncoder.encode("user"));
        user.setRoles(Set.of(roleUser));

        User admin = new User("Admin", "Admin", 30, "admin@mail.ru",
                passwordEncoder.encode("admin"));
        admin.setRoles(Set.of(roleAdmin));

        // сохранение
        userService.saveUser(user);
        userService.saveUser(admin);
    }
}
