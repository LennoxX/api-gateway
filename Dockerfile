# Base image para compilar o projeto
FROM maven:3.9.4-eclipse-temurin-21 AS build

# Diretório de trabalho para o build
WORKDIR /app

# Copia os arquivos do projeto Maven para o container
COPY pom.xml ./
COPY src ./src

# Comando para compilar o projeto e gerar o JAR
RUN mvn clean package -DskipTests

# Base image para rodar o JAR gerado
FROM openjdk:21-jdk-slim

# Diretório de trabalho na imagem final
WORKDIR /app

# Copia o JAR gerado para a imagem final
COPY --from=build /app/target/*.jar app.jar

# Copia o script de inicialização para o container
COPY init.sh /app/init.sh

# Copia os arquivos .pem, se necessário, para a imagem
COPY src/main/resources/*.pem /app/resources/

# Dá permissão de execução ao script
RUN chmod +x /app/init.sh

# Porta exposta pela aplicação
EXPOSE 443

# Comando para rodar o script de inicialização
ENTRYPOINT ["/bin/sh", "/app/init.sh"]


