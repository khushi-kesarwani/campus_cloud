package com.campuscloud.users_service.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.campuscloud.users_service.dto.ApiResponse;
import com.campuscloud.users_service.dto.AdminRegisterRequestDto;
import com.campuscloud.users_service.dto.FacultyRegisterRequestDto;
import com.campuscloud.users_service.dto.LoginRequestDTO;
import com.campuscloud.users_service.dto.LoginResponseDTO;
import com.campuscloud.users_service.dto.StudentRegisterRequestDto;
import com.campuscloud.users_service.entity.RefreshToken;
import com.campuscloud.users_service.entity.User;
import com.campuscloud.users_service.security.CookieUtil;
import com.campuscloud.users_service.security.CsrfTokenUtil;
import com.campuscloud.users_service.security.JwtUtil;
import com.campuscloud.users_service.service.AuthLoginResult;
import com.campuscloud.users_service.service.AuthService;
import com.campuscloud.users_service.service.RefreshTokenService;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor

public class AuthController 
{
    private final RefreshTokenService refreshTokenService;
    private final JwtUtil jwtUtil;
    private final CookieUtil cookieUtil;
    private final CsrfTokenUtil csrfTokenUtil;
    
    private final AuthService authService;
    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponseDTO>> login2(
            @RequestBody LoginRequestDTO request
    ) {
    	log.info("Login request received");
    	log.warn("Password is null during login attempt");
    	
    	if (request.getUsername() == null || request.getUsername().isEmpty()) {
    	    return ResponseEntity.badRequest().build();
    	}

    	if (request.getPassword() == null || request.getPassword().length() < 6) {
    	    return ResponseEntity.badRequest().build();
    	}
        // 1️⃣ Authenticate (internal result)
        AuthLoginResult result = authService.login(request);

        // 2️⃣ Create HTTP-only refresh token cookie
        ResponseCookie refreshCookie =
            cookieUtil.createRefreshTokenCookie(
                result.getRefreshToken(),
                cookieUtil.getRefreshTokenMaxAgeMs()
            );

        // create csrf token cookie
        String csrfToken = csrfTokenUtil.generateToken();
        ResponseCookie csrfCookie = csrfTokenUtil.createCsrfCookie(csrfToken);
        
        // 3️⃣ Build final API response
        LoginResponseDTO response = new LoginResponseDTO(
    	    result.getAccessToken(),
    	    result.getExpiresIn(),
    	    "Bearer",
    	    result.getUserInfo()
    	);

        // 4️⃣ Return response + cookie
        return ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
            .header(HttpHeaders.SET_COOKIE, csrfCookie.toString())
            .body(ApiResponse.success("Login successful", response));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<ApiResponse<LoginResponseDTO>> refreshToken(
            @CookieValue(name = "refreshToken", required = false)
            String refreshTokenValue
    ) {
        if (refreshTokenValue == null) {
            throw new RuntimeException("Refresh token missing");
        }

        // 1️⃣ Find refresh token in DB
        RefreshToken oldRefreshToken =
            refreshTokenService.findByToken(refreshTokenValue)
                .map(refreshTokenService::verifyExpiration)
                .orElseThrow(() ->
                    new RuntimeException("Invalid refresh token")
                );

        User user = oldRefreshToken.getUser();

        // 2️⃣ Rotate refresh token
        refreshTokenService.delete(oldRefreshToken);
        RefreshToken newRefreshToken =
            refreshTokenService.createRefreshToken(user);

        // 3️⃣ Generate new access token
        String newAccessToken = jwtUtil.generateToken(user);

        // 🔄 3.5️⃣ ROTATE CSRF TOKEN (NEW)
        String newCsrfToken = csrfTokenUtil.generateToken();
        ResponseCookie newCsrfCookie =
            csrfTokenUtil.createCsrfCookie(newCsrfToken);

        // 4️⃣ Create new refresh cookie
        ResponseCookie newRefreshCookie =
            cookieUtil.createRefreshTokenCookie(
                newRefreshToken.getToken(),
                cookieUtil.getRefreshTokenMaxAgeMs()
            );
        
        // 5️⃣ Build response DTO
        LoginResponseDTO response = new LoginResponseDTO(
            newAccessToken,
            jwtUtil.getAccessTokenExpirySeconds(),
            "Bearer",
            authService.buildUserInfo(user)
        );

        // 6️⃣ Return response + BOTH rotated cookies
        return ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, newRefreshCookie.toString())
            .header(HttpHeaders.SET_COOKIE, newCsrfCookie.toString())
            .body(ApiResponse.success(response));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            @CookieValue(name = "refreshToken", required = false)
            String refreshTokenValue
    ) {
    	
    	System.out.println("LOGOUT refreshToken cookie = " + refreshTokenValue);
    	
        // 1️⃣ Delete refresh token from DB (if present)
        if (refreshTokenValue != null) {
            refreshTokenService.findByToken(refreshTokenValue)
                    .ifPresent(refreshTokenService::delete);
        }

        // 2️⃣ Delete refresh token cookie
        ResponseCookie deleteRefreshCookie =
                cookieUtil.deleteRefreshTokenCookie();

        // 3️⃣ Delete CSRF cookie
        ResponseCookie deleteCsrfCookie =
                ResponseCookie.from(CsrfTokenUtil.CSRF_COOKIE_NAME, "")
                        .path("/")
                        .maxAge(0)
                        .build();

        // 4️⃣ Return response with cookie deletions
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, deleteRefreshCookie.toString())
                .header(HttpHeaders.SET_COOKIE, deleteCsrfCookie.toString())
                .body(ApiResponse.success("Logged out", null));
    }


}
