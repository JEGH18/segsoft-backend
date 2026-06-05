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
RUN addgroup -S pdgseg && adduser -S pdgseg -G pdgseg
COPY --from=build /workspace/target/*.jar app.jar
RUN chown pdgseg:pdgseg app.jar
USER pdgseg
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
