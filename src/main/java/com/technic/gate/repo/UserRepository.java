package com.technic.gate.repo;

import com.technic.gate.domain.Role;
import com.technic.gate.domain.User;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsernameIgnoreCase(String username);

    boolean existsByUsernameIgnoreCase(String username);

    long countByRole(Role role);

    /**
     * Догружает сервисы вместе с пользователем. Нужно и при логине, и на /verify:
     * коллекция ленивая, а решение о доступе принимается уже вне транзакции.
     */
    @EntityGraph(attributePaths = "services")
    Optional<User> findWithServicesByUsernameIgnoreCase(String username);

    @EntityGraph(attributePaths = "services")
    Optional<User> findWithServicesById(Long id);

    @EntityGraph(attributePaths = "services")
    @Query("select u from User u order by u.username")
    List<User> findAllWithServices();
}
