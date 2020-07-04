FROM ubuntu:18.04
RUN mkdir -p /home/ohk990102/dpwn/test
WORKDIR /home/ohk990102/dpwn/test
COPY ./ ./
RUN chmod +x ./realloc
RUN apt-get update && apt-get install -y gdb gdbserver && rm -rf /var/lib/apt/lists/*
EXPOSE 1234
CMD [ "./realloc" ]
