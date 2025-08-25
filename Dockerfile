FROM alpine
LABEL name=ddns-go
LABEL url=https://github.com/jeessy2/ddns-go
LABEL maintainer='Drixn <i@drixn.com>'
RUN apk add --no-cache curl grep

WORKDIR /app
COPY ddns-go /app/
COPY zoneinfo /usr/share/zoneinfo
ENV TZ=Asia/Shanghai
EXPOSE 9876
ENTRYPOINT ["/app/ddns-go"]
CMD ["-l", ":9875", "-f", "300"] 
