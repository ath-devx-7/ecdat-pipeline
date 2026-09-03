# Weak-crypto Java service — ECDAT demo target D (SPEC.md §14).
#
# No build tool: JEP 330 single-file source launch runs HashDemo.java directly,
# which keeps the target a source tree the code collector can read rather than a
# jar it cannot.
FROM eclipse-temurin:17-jdk

WORKDIR /opt/app
COPY HashDemo.java java.security ./

# Single `=` overrides only the properties named in the file and leaves the rest
# of the JDK's own java.security in place. `==` would replace the whole file and
# break the runtime.
CMD ["java", "-Djava.security.properties=/opt/app/java.security", "HashDemo.java"]
