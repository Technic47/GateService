# JVM-сборка: то, чем удобно пользоваться при отладке и первом деплое.
# Финальный native-образ собирается отдельно — см. Dockerfile.native.

FROM maven:3.9-eclipse-temurin-25 AS build
WORKDIR /build

# Зависимости отдельным слоем: правка исходников не заставляет заново тянуть весь репозиторий.
COPY pom.xml .
RUN mvn -B dependency:go-offline

COPY src ./src
RUN mvn -B clean package -DskipTests

FROM eclipse-temurin:25-jre-alpine
WORKDIR /app

# Не root: гейт смотрит наружу, пусть и через Nginx.
RUN addgroup -S gate && adduser -S -G gate gate
USER gate

COPY --from=build /build/target/gate-service-*.jar app.jar

EXPOSE 9000

# Внутри контейнера слушаем все интерфейсы — иначе порт не пробросится наружу.
# Ограничение доступа снаружи делается публикацией порта на 127.0.0.1 в compose.
ENV GATE_BIND_ADDRESS=0.0.0.0

# 2 ГБ на VPS делятся между всем остальным, что там уже крутится.
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=60 -XX:+UseSerialGC"

ENTRYPOINT ["java", "-jar", "app.jar"]
