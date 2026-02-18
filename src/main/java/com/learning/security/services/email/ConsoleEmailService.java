package com.learning.security.services.email;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

/**
 * Fallback email service that logs emails to console.
 * Useful for local development and testing when no email provider is configured.
 * <p>
 * Activated when {@code yousuf.app.email.provider=console} or when the property is not set.
 */
@Service
@ConditionalOnProperty(name = "yousuf.app.email.provider", havingValue = "console", matchIfMissing = true)
@Slf4j
public class ConsoleEmailService implements EmailService {

    @Override
    public void sendEmail(String to, String subject, String htmlBody) {
        log.info("╔══════════════════════════════════════════════════════════════");
        log.info("║ 📧 EMAIL (Console Mode)");
        log.info("╠══════════════════════════════════════════════════════════════");
        log.info("║ To:      {}", to);
        log.info("║ Subject: {}", subject);
        log.info("╠══════════════════════════════════════════════════════════════");
        log.info("║ Body (HTML stripped):");
        log.info("║ {}", stripHtml(htmlBody));
        log.info("╚══════════════════════════════════════════════════════════════");
    }

    private String stripHtml(String html) {
        if (html == null) return "";
        // Simple HTML tag stripping for console readability
        return html.replaceAll("<[^>]*>", " ")
                    .replaceAll("&nbsp;", " ")
                    .replaceAll("&amp;", "&")
                    .replaceAll("\\s+", " ")
                    .trim();
    }
}
