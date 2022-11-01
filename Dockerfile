FROM node:latest

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app
COPY package.json /usr/src/app/
EXPOSE 3000

ENV NODE_ENV=development
RUN npm install -g nodemon && npm install
COPY . /usr/src/app
CMD [ "nodemon", "/usr/src/app" ]