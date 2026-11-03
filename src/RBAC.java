/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author hp
 */
import java.util.*;

public class RBAC {

    // role name -> set of "object:action" permission strings
    private final Map<String, Set<String>> roles = new HashMap<>();
    // user name -> set of role names
    private final Map<String, Set<String>> userRoles = new HashMap<>();

    public void addRole(String role) {
        roles.putIfAbsent(role, new HashSet<>());
    }

    public void grantPermission(String role, String obj, String action) {
        if (!roles.containsKey(role)) {
            throw new IllegalArgumentException("Unknown role: " + role);
        }
        roles.get(role).add(obj + ":" + action);
    }

    public void assignRole(String user, String role) {
        if (!roles.containsKey(role)) {
            throw new IllegalArgumentException("Unknown role: " + role);
        }
        userRoles.computeIfAbsent(user, k -> new HashSet<>()).add(role);
    }

    public boolean checkAccess(String user, String obj, String action) {
        String permission = obj + ":" + action;
        for (String role : userRoles.getOrDefault(user, Collections.emptySet())) {
            if (roles.get(role).contains(permission)) {
                return true;
            }
        }
        return false;
    }

    public static void main(String[] args) {
        RBAC rbac = new RBAC();

        for (String role : List.of("Admin", "Manager", "Customer")) {
            rbac.addRole(role);
        }

        // Permissions on the "Account" object
        for (String action : List.of("create", "view", "update", "delete")) {
            rbac.grantPermission("Admin", "Account", action);
        }
        for (String action : List.of("view", "update")) {
            rbac.grantPermission("Manager", "Account", action);
        }
        rbac.grantPermission("Customer", "Account", "view");

        // User-to-role assignments
        rbac.assignRole("alice", "Admin");
        rbac.assignRole("bob", "Manager");
        rbac.assignRole("carol", "Customer");

        System.out.printf("%-8s %-8s %s%n", "User", "Action", "Result");
        System.out.println("-".repeat(28));
        for (String user : List.of("alice", "bob", "carol")) {
            for (String action : List.of("create", "view", "update", "delete")) {
                boolean allowed = rbac.checkAccess(user, "Account", action);
                System.out.printf("%-8s %-8s %s%n", user, action, allowed ? "ALLOWED" : "DENIED");
            }
        }
    }
}