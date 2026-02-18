package com.learning.security.services.email;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

/**
 * Sends emails via a Supabase Edge Function.
 * <p>
 * The Edge Function should accept a JSON body: {@code {"to", "subject", "html"}}
 * and forward it to a transactional email provider (Resend, SendGrid, etc.).
 * <p>
 * Activated when {@code yousuf.app.email.provider=supabase}.
 */
@Service
@ConditionalOnProperty(name = "yousuf.app.email.provider", havingValue = "supabase")
@Slf4j
public class SupabaseEmailService implements EmailService {

    @Value("${yousuf.app.email.supabase.edge-function-url}")
    private String edgeFunctionUrl;

    @Value("${yousuf.app.email.supabase.service-role-key}")
    private String serviceRoleKey;

    private final RestTemplate restTemplate = new RestTemplate();

    @Override
    public void sendEmail(String to, String subject, String htmlBody) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(serviceRoleKey);

            Map<String, String> body = Map.of(
                "to", to,
                "subject", subject,
                "html", htmlBody
            );

            HttpEntity<Map<String, String>> request = new HttpEntity<>(body, headers);

            ResponseEntity<String> response = restTemplate.exchange(
                edgeFunctionUrl, HttpMethod.POST, request, String.class);

            if (response.getStatusCode().is2xxSuccessful()) {
                log.info("Email sent successfully to: {}", to);
            } else {
                log.error("Failed to send email to: {}. Status: {}", to, response.getStatusCode());
                throw new RuntimeException("Email provider returned non-success status: " + response.getStatusCode());
            }
        } catch (Exception e) {
            log.error("Error sending email to: {}", to, e);
            throw new RuntimeException("Failed to send email: " + e.getMessage(), e);
        }
    }
}
