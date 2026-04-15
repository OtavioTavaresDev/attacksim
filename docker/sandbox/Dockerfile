FROM python:3.11-slim

WORKDIR /app

# Copia o arquivo de dependências do backend
COPY backend/requirements.txt .

# Instala as dependências necessárias para os módulos de ataque
RUN pip install --no-cache-dir -r requirements.txt

# Copia o código dos módulos e configurações
COPY backend/app/modules /app/app/modules
COPY backend/app/core/config.py /app/app/core/
COPY backend/app/schemas /app/app/schemas

# Cria um usuário não-root por segurança
RUN useradd -m -u 1000 sandbox && chown -R sandbox:sandbox /app
USER sandbox

# Comando padrão (será sobrescrito na execução)
CMD ["python", "-c", "print('Sandbox ready')"]
