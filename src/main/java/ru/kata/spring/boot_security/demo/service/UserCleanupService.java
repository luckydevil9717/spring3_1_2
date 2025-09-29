package ru.kata.spring.boot_security.demo.service;

import jakarta.transaction.Transactional;
import org.springframework.boot.CommandLineRunner;
import ru.kata.spring.boot_security.demo.model.User;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import ru.kata.spring.boot_security.demo.repository.UserRepository;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class UserCleanupService {

    private final UserRepository userRepository;

    public UserCleanupService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Transactional
    public void removeDuplicateEmails() {
        List<User> allUsers = userRepository.findAll();
        Map<String, User> uniqueEmails = new HashMap<>();

        for (User user : allUsers) {
            String email = user.getEmail();
            if (email == null || email.isBlank()) {
                continue; // пропускаем пользователей без email
            }

            email = email.toLowerCase().trim(); // нормализуем
            if (!uniqueEmails.containsKey(email)) {
                uniqueEmails.put(email, user);
            } else {
                // удаляем дубликат
                userRepository.delete(user);
            }
        }
    }


    @Component
    public class CleanupRunner implements CommandLineRunner {

        private final UserCleanupService cleanupService;

        public CleanupRunner(UserCleanupService cleanupService) {
            this.cleanupService = cleanupService;
        }

        @Override
        public void run(String... args) throws Exception {
            cleanupService.removeDuplicateEmails();
            System.out.println("Duplicate emails cleaned up!");
        }
    }
}

