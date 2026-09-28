package co.icesi.pdgseg;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class PdgsegApplication {

    public static void main(String[] args) {
        SpringApplication.run(PdgsegApplication.class, args);
    }
}
