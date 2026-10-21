package co.icesi.pdgseg.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ProdAccountsInitializerTest {

    private static final String VALID =
            "admin:SECURITY_ADMIN:Adm1n-Prod-Pass;auditor:AUDITOR:Aud1tor-Prod-Pass\ndev:DEVELOPER:Dev-Prod-Pass:con:dos-puntos";

    @Test
    void parse_readsEntriesSeparatedBySemicolonsOrLines_andKeepsColonsInPasswords() {
        List<ProdAccountsInitializer.Account> accounts = ProdAccountsInitializer.parse(VALID);

        assertThat(accounts).extracting(ProdAccountsInitializer.Account::username)
                .containsExactly("admin", "auditor", "dev");
        assertThat(accounts.get(2).password()).isEqualTo("Dev-Prod-Pass:con:dos-puntos");
        assertThat(accounts.get(0).role()).isEqualTo("SECURITY_ADMIN");
    }

    @Test
    void account_toStringNeverIncludesThePassword() {
        assertThat(ProdAccountsInitializer.parse(VALID).toString()).doesNotContain("Prod-Pass");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\n;\n"})
    void parse_rejectsAMissingVariable(String spec) {
        assertThatThrownBy(() -> ProdAccountsInitializer.parse(spec))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no está definida");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "admin:SECURITY_ADMIN",                                // sin contraseña
            "admin:ROOT:Adm1n-Prod-Pass",                          // rol inexistente
            "admin:SECURITY_ADMIN:corta",                          // menos de 12 caracteres
            "ad:SECURITY_ADMIN:Adm1n-Prod-Pass",                   // usuario muy corto
            "admin user:SECURITY_ADMIN:Adm1n-Prod-Pass",           // espacio en el usuario
            "admin:SECURITY_ADMIN:Adm1n-Prod-Pass;admin:AUDITOR:Otra-Pass-Larga", // duplicado
            "dev:DEVELOPER:Dev-Prod-Pass-1",                       // ningún SECURITY_ADMIN
    })
    void parse_rejectsInvalidEntries(String spec) {
        assertThatThrownBy(() -> ProdAccountsInitializer.parse(spec))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageStartingWith("SEGSOFT_ACCOUNTS inválida");
    }

    @Test
    void parse_rejectsEveryPublicDemoPassword() {
        ProdAccountsInitializer.PUBLIC_DEMO_PASSWORDS.forEach((username, publicPassword) ->
                assertThatThrownBy(() -> ProdAccountsInitializer.parse("admin:SECURITY_ADMIN:" + publicPassword))
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("al menos"));
    }

    @Test
    void run_setsTheConfiguredAccounts_andDisablesDemoAccountsThatKeepTheirPublicPassword() {
        AccountSeeder seeder = mock(AccountSeeder.class);
        when(seeder.hasPassword("usuario", "usuario123")).thenReturn(true);
        when(seeder.hasPassword("admin", "admin123")).thenReturn(true); // configurado: se reemplaza, no se deshabilita

        new ProdAccountsInitializer(seeder, VALID).run();

        verify(seeder).replace("admin", "Adm1n-Prod-Pass", "SECURITY_ADMIN");
        verify(seeder).replace("auditor", "Aud1tor-Prod-Pass", "AUDITOR");
        verify(seeder).replace("dev", "Dev-Prod-Pass:con:dos-puntos", "DEVELOPER");
        verify(seeder).disable("usuario");
        verify(seeder, never()).disable("admin");
        verify(seeder, never()).hasPassword("admin", "admin123");
    }

    @Test
    void run_failsBeforeTouchingTheDatabaseWhenTheVariableIsInvalid() {
        AccountSeeder seeder = mock(AccountSeeder.class);

        assertThatThrownBy(() -> new ProdAccountsInitializer(seeder, "").run())
                .isInstanceOf(IllegalStateException.class);
        verify(seeder, never()).replace(anyString(), anyString(), anyString());
    }
}
