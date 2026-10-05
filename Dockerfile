# JVM-сборка: то, чем удобно пользоваться при отладке и первом деплое.
# Финальный native-образ собирается отдельно — см. Dockerfile.native.

FROM maven:3.9-eclipse-temurin-25 AS build
WORKDIR /build

# gate-auth-core (соседний проект ../gate-auth) пока не опубликован в Maven Central:
# собираем его здесь же из дополнительного контекста сборки "gateauth".
#   compose:      build.additional_contexts.gateauth: ../gate-auth   (уже прописано)
#   docker build: docker build --build-context gateauth=../gate-auth .
# Pom стартера нужен только чтобы Maven прочитал reactor; сам стартер не собирается.
# После публикации в Central этот блок удалить.
COPY --from=gateauth pom.xml /gate-auth/pom.xml
COPY --from=gateauth gate-auth-core/pom.xml /gate-auth/gate-auth-core/pom.xml
COPY --from=gateauth gate-auth-core/src /gate-auth/gate-auth-core/src
COPY --from=gateauth gate-auth-spring-boot-starter/pom.xml /gate-auth/gate-auth-spring-boot-starter/pom.xml
RUN mvn -B -q -f /gate-auth/pom.xml -pl gate-auth-core -am install -DskipTests

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
