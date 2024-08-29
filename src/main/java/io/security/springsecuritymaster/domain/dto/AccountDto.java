package io.security.springsecuritymaster.domain.dto;

import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccountDto {
    private String id;
    private String username;
    private String password;
    private int age;
    private String roles;
}
