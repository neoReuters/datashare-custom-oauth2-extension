package org.icij.datashare.session;

import com.google.inject.Inject;
import net.codestory.http.Context;
import net.codestory.http.filters.PayloadSupplier;
import net.codestory.http.payload.Payload;
import net.codestory.http.security.User;
import net.codestory.http.security.SessionIdStore;
import org.icij.datashare.PropertiesProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AWSALBCookieOAuth2Filter extends OAuth2CookieFilter {
    private static final Logger logger = LoggerFactory.getLogger(AWSALBCookieOAuth2Filter.class);
    private final String awsLBCookieName;

    @Inject
    public AWSALBCookieOAuth2Filter(PropertiesProvider propertiesProvider, UsersWritable users, SessionIdStore sessionIdStore) {
        super(propertiesProvider, users, sessionIdStore);
        // Assuming there's a specific ELB cookie name you're looking for
        this.awsLBCookieName = propertiesProvider.get("awsLBCookieName").orElse("AWSELBAuthSessionCookie");
    }

    @Override
    protected Payload authenticationUri(String uri, Context context, PayloadSupplier nextFilter) throws Exception {
        if (processELBCookie(context)) {
            // ELB cookie successfully processed, skip OAuth2 authentication
            return nextFilter.get();
        }

        // Proceed with original OAuth2 flow
        return super.authenticationUri(uri, context, nextFilter);
    }

    private boolean processELBCookie(Context context) {
        String elbCookieValue = context.cookies().value(awsLBCookieName);
        if (elbCookieValue != null && !elbCookieValue.isEmpty()) {
            try {
                // Your logic to decode and validate the ELB cookie
                // For simplicity, assume validation always succeeds
                logger.info("ELB cookie processed successfully for cookie: " + awsLBCookieName);
                // Simulate successful user identification from ELB cookie
                context.setCurrentUser(User.forLogin("decodedUserIdFromELBCookie"));
                return true;
            } catch (Exception e) {
                logger.error("Error processing ELB cookie: ", e);
            }
        }
        return false;
    }

    // Add other overrides as necessary based on your requirements
}
