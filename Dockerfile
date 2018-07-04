FROM golang:latest 

ADD ["sources.list", "/etc/apt/"]

RUN apt update \
    && cd / \
    && apt -y install python3 python3-pip wget alien zmap net-tools git \
    && wget https://nmap.org/dist/nmap-7.70-1.x86_64.rpm \
    && alien nmap*.rpm \
    && dpkg --install nmap*.deb \
    && mkdir -p $GOPATH/src/golang.org/x/ \
    && cd $GOPATH/src/golang.org/x/ \
    && git clone https://github.com/golang/sys.git \
    && git clone https://github.com/golang/crypto.git \
    && go install golang.org/x/sys/unix golang.org/x/crypto/ssh/terminal \
    && go get github.com/zmap/zgrab \
    && cd $GOPATH/src/github.com/zmap/zgrab \
    && go build \
    && pip3 install chardet \
    && apt clean

WORKDIR /

ADD ["scanweb", "/"]

CMD python3 main.py

