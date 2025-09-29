package ru.kata.spring.boot_security.demo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.service.RoleServiceInterface;
import ru.kata.spring.boot_security.demo.service.UserService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;

@Controller
@RequestMapping("/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final UserService userService;
    private final RoleServiceInterface roleService;

    public AdminController(UserService userService, RoleServiceInterface roleService) {
        this.userService = userService;
        this.roleService = roleService;
    }

    // Страница со списком пользователей
    @GetMapping("/users")
    public String listUsers(Model model, @AuthenticationPrincipal User user) {
        model.addAttribute("users", userService.getAllUsers());
        model.addAttribute("currentUser", user != null ? user : new User()); // если null — пустой объект
        model.addAttribute("allRoles", roleService.getAllRoles());
        return "admin/users";
    }

    // Форма добавления нового пользователя
    @GetMapping("/users/new")
    public String newUserForm(Model model, @AuthenticationPrincipal User currentUser) {
        model.addAttribute("user", new User());
        model.addAttribute("allRoles", roleService.getAllRoles());
        model.addAttribute("currentUser", currentUser); // чтобы шапка работала
        return "admin/newUser";
    }

    @PostMapping("/users/save")
    public String saveUser(@ModelAttribute("user") User user, @RequestParam("roleIds") Long[] roleIds, Model model) {
        if (userService.existsByEmail(user.getEmail())) { // проверка дублирования
            model.addAttribute("errorMessage", "Пользователь с таким email уже существует!");
            model.addAttribute("allRoles", roleService.getAllRoles());
            return "admin/newUser";
        }
        userService.saveUserWithRoles(user, roleIds);
        return "redirect:/admin/users";
    }

    @PostMapping("/users/update")
    public String updateUser(@ModelAttribute("user") User user, @RequestParam("roleIds") Long[] roleIds, Model model) {
        if (userService.existsByEmailExceptId(user.getEmail(), user.getId())) { // проверка для редактирования
            model.addAttribute("errorMessage", "Пользователь с таким email уже существует!");
            model.addAttribute("user", user);
            model.addAttribute("allRoles", roleService.getAllRoles());
            return "admin/editUser";
        }
        userService.updateUserWithRoles(user, roleIds);
        return "redirect:/admin/users";
    }

    // Форма редактирования пользователя
    @GetMapping("/users/edit/{id}")
    public String editUserForm(@PathVariable Long id, Model model,
                               @AuthenticationPrincipal User currentUser) {
        User user = userService.getUser(id);
        model.addAttribute("user", user);
        model.addAttribute("allRoles", roleService.getAllRoles());
        model.addAttribute("currentUser", currentUser); // шапка
        return "admin/editUser";
    }



    // Удаление пользователя
    @GetMapping("/users/delete/{id}")
    public String deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return "redirect:/admin/users";
    }
}