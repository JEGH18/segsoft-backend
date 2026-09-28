package co.icesi.pdgseg.entity;

import co.icesi.pdgseg.entity.enums.RoleType;
import jakarta.persistence.*;
import java.util.UUID;

@Entity
@Table(name = "roles")
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(unique = true, nullable = false, length = 50)
    private RoleType name;

    public Role() {}

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public RoleType getName() { return name; }
    public void setName(RoleType name) { this.name = name; }

    public String getNameAsString() { return name != null ? name.name() : null; }
}
