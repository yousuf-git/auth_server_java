package com.learning.security.services.email;

/**
 * Generic email service interface.
 * Implementations can use Supabase Edge Functions, SMTP, SendGrid, AWS SES, etc.
 * Switch providers by setting {@code yousuf.app.email.provider} property.
 */
public interface EmailService {

    /**
     * Sends an email with the given HTML body.
     *
     * @param to      recipient email address
     * @param subject email subject line
     * @param htmlBody pre-rendered HTML content
     */
    void sendEmail(String to, String subject, String htmlBody);
}
