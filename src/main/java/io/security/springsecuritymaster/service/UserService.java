package io.security.springsecuritymaster.service;

import io.security.springsecuritymaster.domain.entity.Account;
import io.security.springsecuritymaster.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class UserService {

    private final UserRepository userRepository;

    public void createUser(Account account) {
       userRepository.save(account);
    }
}
