FROM eclipse-temurin:17-alpine
ARG JAR_FILE=*.jar
COPY ${JAR_FILE} app.jar
EXPOSE 9090
ENTRYPOINT ["java","-jar","/app.jar"]
