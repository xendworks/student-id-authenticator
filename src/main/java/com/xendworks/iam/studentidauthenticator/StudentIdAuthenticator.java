package com.xendworks.iam.studentidauthenticator;

import java.util.List;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;
import javax.ws.rs.core.MultivaluedMap;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.models.*;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.events.Errors;
import javax.ws.rs.core.Response;
import org.keycloak.services.messages.Messages;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.Details;
import org.keycloak.models.ModelDuplicateException;

public class StudentIdAuthenticator extends UsernamePasswordForm implements Authenticator {

    private static final Logger logger = Logger.getLogger(StudentIdAuthenticator.class);
    @Override
    public boolean validateUserAndPassword(AuthenticationFlowContext context, MultivaluedMap inputData) {
        String username = String.valueOf(inputData.getFirst(AuthenticationManager.FORM_USERNAME));
        if (username == null) {
            context.getEvent().error(Errors.USER_NOT_FOUND);
            Response challengeResponse = challenge(context, Messages.INVALID_USER);
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return false;
        }

        // remove leading and trailing whitespace
        username = username.trim();
        context.getEvent().detail(Details.USERNAME, username);
        context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, username);
        UserModel user = null;
        try {
            List<UserModel> users = context.getSession().users().searchForUserByUserAttributeStream(context.getRealm(),"student_id", username).collect(Collectors.toList());
            System.out.println(users.get(0).getUsername());
            if (users != null && users.size() == 1) {
                user = users.get(0);
            }
        } catch (ModelDuplicateException mde) {
            if (mde.getDuplicateFieldName() != null && mde.getDuplicateFieldName().equals(UserModel.EMAIL)) {
                setDuplicateUserChallenge(context, Errors.EMAIL_IN_USE, Messages.EMAIL_EXISTS, AuthenticationFlowError.INVALID_USER);
            } else {
                setDuplicateUserChallenge(context, Errors.USERNAME_IN_USE, Messages.USERNAME_EXISTS, AuthenticationFlowError.INVALID_USER);
            }
            logger.log(Logger.Level.ERROR,"Authentication failed at duplicate user condition");
            return false;
        }
        if(user==null){
            logger.log(Logger.Level.ERROR,"Authentication failed at User not found");
            return false;
        }

        if (!validatePassword(context, user, inputData,true)) {
            logger.log(Logger.Level.ERROR,"Authentication failed at valid password condition");
            return false;
        }

        if (!enabledUser(context, user)) {
            logger.log(Logger.Level.ERROR,"Authentication failed at enabled user condition");
            return false;
        }

        String rememberMe = String.valueOf(inputData.getFirst("rememberMe"));
        boolean remember = rememberMe != null && rememberMe.equalsIgnoreCase("on");
        if (remember) {
            context.getAuthenticationSession().setAuthNote(Details.REMEMBER_ME, "true");
            context.getEvent().detail(Details.REMEMBER_ME, "true");
        } else {
            context.getAuthenticationSession().removeAuthNote(Details.REMEMBER_ME);
        }
        context.setUser(user);

        return true;
    }

}
