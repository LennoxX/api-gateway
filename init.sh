#!/bin/sh

# Verifica se existem arquivos .pem no diretório /app/resources
if ls /app/resources/*.pem 1> /dev/null 2>&1; then
    # Copia todos os arquivos .pem encontrados para /tmp/
    cp /app/resources/*.pem /tmp/
    echo "Arquivos .pem copiados para /tmp."
else
    echo "Nenhum arquivo .pem encontrado."
fi

# Importar os arquivos .pem para o keystore com alias baseado no nome do arquivo
for pem in /tmp/*.pem; do
    # Extrai o nome do arquivo sem a extensão .pem
    alias_name=$(basename "$pem" .pem)
    
    # Importa o certificado para o keystore com o alias extraído
    keytool -import -alias "$alias_name" -file "$pem" -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit -noprompt
    echo "Certificado $pem importado para o keystore com alias $alias_name."
done

# Executar a aplicação
java -jar /app/app.jar