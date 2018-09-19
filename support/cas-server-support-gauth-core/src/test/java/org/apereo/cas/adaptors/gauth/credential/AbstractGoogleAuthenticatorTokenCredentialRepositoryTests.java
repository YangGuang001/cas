package org.apereo.cas.adaptors.gauth.credential;

import org.apereo.cas.CipherExecutor;
import org.apereo.cas.authentication.OneTimeTokenAccount;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialRepository;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.IGoogleAuthenticator;
import lombok.Getter;
import lombok.val;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.springframework.test.context.junit4.rules.SpringClassRule;
import org.springframework.test.context.junit4.rules.SpringMethodRule;

import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.LinkedHashMap;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * This is {@link AbstractGoogleAuthenticatorTokenCredentialRepositoryTests}.
 *
 * @author Timur Duehr
 * @since 6.0.0
 */
@Getter
public abstract class AbstractGoogleAuthenticatorTokenCredentialRepositoryTests {
    @ClassRule
    public static final SpringClassRule SPRING_CLASS_RULE = new SpringClassRule();

    @Rule
    public final SpringMethodRule springMethodRule = new SpringMethodRule();

    private IGoogleAuthenticator google;

    @Mock
    private CipherExecutor<String, String> cipherExecutor;

    private HashMap<Pair<String, String>, OneTimeTokenAccount> accountHashMap = new LinkedHashMap<>();

    public OneTimeTokenAccount getAccount(final String testName, final String username) {
        return accountHashMap.computeIfAbsent(Pair.of(testName, username), pair -> getRepository(pair.getLeft()).create(pair.getRight()));
    }

    @Before
    public void initialize() {
        val bldr = new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder();
        this.google = new GoogleAuthenticator(bldr.build());
    }

    @Test
    public void verifyCreate() {
        val acct = getAccount("verifyCreate", "casuser");
        assertNotNull(acct);
    }

    @Test
    public void verifyGet() {
        val repo = getRepository("verifyGet");
        val acct = repo.get("casuser");
        assertNull(acct);
        val acct2 = getAccount("verifyGet", "casuser");
        repo.save(acct2.getUsername(), acct2.getSecretKey(), acct2.getValidationCode(), acct2.getScratchCodes());
        val acct3 = repo.get("casuser");
        assertEquals(acct2.getUsername(), acct3.getUsername());
        assertEquals(acct2.getValidationCode(), acct3.getValidationCode());
        assertEquals(acct2.getSecretKey(), acct3.getSecretKey());
        assertEquals(acct2.getScratchCodes(), acct3.getScratchCodes());
        assertEquals(acct2.getRegistrationDate().truncatedTo(ChronoUnit.SECONDS), acct3.getRegistrationDate().withFixedOffsetZone().truncatedTo(ChronoUnit.SECONDS));
    }

    @Test
    public void verifyGetWithDecodedSecret() {
        // given
        when(cipherExecutor.encode("plain_secret")).thenReturn("abc321");
        when(cipherExecutor.decode("abc321")).thenReturn("plain_secret");
        val repo = getRepository("verifyGetWithDecodedSecret");
        var acct = repo.create("casuser");
        acct.setSecretKey("plain_secret");
        repo.save(acct.getUsername(), acct.getSecretKey(), acct.getValidationCode(), acct.getScratchCodes());

        // when
        acct = repo.get("casuser");

        // then
        assertEquals("plain_secret", acct.getSecretKey());
    }

    abstract OneTimeTokenCredentialRepository getRepository(String testName);
}
