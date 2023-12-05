package com.example.springsecurity.user;

import jakarta.persistence.*;

import java.util.Optional;

import static java.util.Optional.ofNullable;

@Entity
@Table(name = "users")
public class User {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "username")
    private String username;

    @Column(name = "provider")
    private String provider;

    @Column(name = "provider_id")
    private String providerId;

    @Column(name = "profile_image")
    private String profileImage;

    @ManyToOne(optional = false)
    @JoinColumn(name = "group_id")
    private Group group;

    protected User() {/*no-op*/}

    public User(String username, String provider, String providerId, String profileImage, Group group) {
        checkUsername(username);
        checkProvider(provider);
        checkProviderId(providerId);
        checkGroup(group);

        this.username = username;
        this.provider = provider;
        this.providerId = providerId;
        this.profileImage = profileImage;
        this.group = group;
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getProvider() {
        return provider;
    }

    public String getProviderId() {
        return providerId;
    }

    public Optional<String> getProfileImage() {
        return ofNullable(profileImage);
    }

    public Group getGroup() {
        return group;
    }
    private void checkUsername(String username) {
        if (username == null) {
            throw new IllegalArgumentException("username must be provided.");
        }
    }

    private void checkProvider(String provider) {
        if (provider == null) {
            throw new IllegalArgumentException("provider must be provided.");
        }
    }

    private void checkProviderId(String providerId) {
        if (providerId == null) {
            throw new IllegalArgumentException("providerId must be provided.");
        }
    }

    private void checkGroup(Group group) {
        if (group == null) {
            throw new IllegalArgumentException("group must be provided.");
        }
    }
}
