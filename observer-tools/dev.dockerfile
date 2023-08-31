FROM node:16.8-bullseye
WORKDIR /app

RUN apt update --yes && apt upgrade --yes
RUN apt install build-essential libssl-dev openssl lsb-base bash telnet procps python3 rsyslog nano --yes

COPY linux-amd64_deb.tgz /app/
RUN tar -xvf linux-amd64_deb.tgz
WORKDIR /app/linux-amd64_deb
RUN ./install.sh kc1 lsb-cprocsp-devel

COPY lib /app/lib/
WORKDIR /app/lib
ENV LD_LIBRARY_PATH=/opt/cprocsp/lib/amd64
RUN gcc -fPIC -DPIC -Wall -c -g gosthash2012.c curve.c \
    -lpthread -lssl -lcrypto -lssp -lcapi10 -lcapi20 -lrdrsup -L/opt/cprocsp/lib/amd64 \
    -DSIZEOF_VOID_P=8 -DHAVE_LIMITS_H -DUNIX -D_COMPACT -DHAVE_STDINT_H \
    -I/opt/cprocsp/includes -I/opt/cprocsp/include/cpcsp -I/usr/include/openssl/
RUN gcc -shared *.o -o libgostcrypto.so -L/opt/cprocsp/lib/amd64 -lcapi10 -lcapi20 -lssl -lcrypto -lssp  -lrdrsup

WORKDIR /app
COPY tsconfig.build.json tsconfig.build.json
COPY tsconfig.json tsconfig.json
COPY package.json .
COPY package-lock.json .
RUN npm i

CMD ["sh", "-c", "service rsyslog start ; tail -f /dev/null"]
CMD /bin/bash
