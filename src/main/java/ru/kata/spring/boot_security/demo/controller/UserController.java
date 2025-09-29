    package ru.kata.spring.boot_security.demo.controller;

    import org.springframework.beans.factory.annotation.Autowired;
    import org.springframework.security.core.annotation.AuthenticationPrincipal;

    import org.springframework.stereotype.Controller;
    import org.springframework.ui.Model;
    import org.springframework.web.bind.annotation.GetMapping;
    import ru.kata.spring.boot_security.demo.model.User;
    import ru.kata.spring.boot_security.demo.repository.RoleRepository;
    import ru.kata.spring.boot_security.demo.service.RoleServiceImpl;

    @Controller
    public class UserController {

        @Autowired
        private RoleRepository roleRepository;

        @GetMapping("/user")
        public String userPage(Model model, @AuthenticationPrincipal User user) {
            model.addAttribute("user", user);
            model.addAttribute("allRoles", roleRepository.findAll());
            return "user";
        }
    }