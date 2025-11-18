# Dockerfile para Frontend
FROM node:22-alpine

# Directorio de trabajo
WORKDIR /app

# Copiar archivos de dependencias
COPY package*.json ./

# Instalar dependencias
RUN npm install

# Copiar el resto del código
COPY . .

# Exponer puerto
EXPOSE 5173

# Comando por defecto
CMD ["npm", "run", "dev", "--", "--host"]
