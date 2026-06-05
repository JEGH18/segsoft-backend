# Stage 1: build
FROM gradle:8.10.1-jdk17 AS build
WORKDIR /workspace
COPY build.gradle settings.gradle ./
COPY gradle ./gradle
RUN gradle dependencies --no-daemon -q
COPY src ./src
RUN gradle bootJar --no-daemon -x test

# Stage 2: runtime
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
RUN addgroup -S pdgseg && adduser -S pdgseg -G pdgseg
COPY --from=build /workspace/build/libs/*.jar app.jar
RUN chown pdgseg:pdgseg app.jar
USER pdgseg
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
