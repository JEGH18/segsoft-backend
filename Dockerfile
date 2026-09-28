# Stage 1: build
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /workspace
COPY pom.xml .
RUN mvn dependency:go-offline -B
COPY src ./src
RUN mvn package -DskipTests -B

# Stage 2: runtime
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
# GitCloneService shells out to the system "git" binary -- the base JRE image
# doesn't include it, which made every "clone from Git URL" request fail with
# "No se pudo ejecutar git clone" (ProcessBuilder couldn't even launch it).
RUN apk add --no-cache git
RUN addgroup -g 10001 -S pdgseg && adduser -u 10001 -S pdgseg -G pdgseg
COPY --from=build /workspace/target/*.jar app.jar
RUN chown pdgseg:pdgseg app.jar \
    && mkdir -p /tmp/pdgseg-sandbox \
    && chown pdgseg:pdgseg /tmp/pdgseg-sandbox
USER pdgseg
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
