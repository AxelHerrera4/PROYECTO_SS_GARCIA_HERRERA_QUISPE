# Dockerfile para Backend
FROM node:22-alpine

# Directorio de trabajo
WORKDIR /app

# Copiar archivos de dependencias
COPY package*.json ./

# Instalar dependencias
RUN npm install

# Copiar el resto del código
COPY . .

# Crear carpeta de uploads si no existe
RUN mkdir -p uploads

# Exponer puerto
EXPOSE 5000

# Comando por defecto
CMD ["npm", "run", "dev"]
