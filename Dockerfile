# log4j2 #4255 lab — a vulnerable serialized-LogEvent receiver.
#
# Fetches the OFFICIAL Log4j jars + commons-collections 3.2.1 from Maven Central
# (the only outbound traffic this lab makes) and compiles the tiny Receiver.
#
#   build:  docker build -t log4j4255 .
#   run  :  docker run --rm -p 4560:4560 log4j4255                 # vulnerable
#           docker run --rm -p 4560:4560 -e MITIGATE=1 log4j4255   # patched JVM
FROM eclipse-temurin:17-jdk

# Pin the whole affected story to one version. Range is 2.8.0–2.26.1; 2.26.1 is HEAD.
ARG LVER=2.26.1
ARG CCVER=3.2.1
WORKDIR /lab

# Official artifacts, straight from Maven Central.
RUN set -eux; B=https://repo1.maven.org/maven2; \
    curl -fsSL "$B/org/apache/logging/log4j/log4j-api/$LVER/log4j-api-$LVER.jar"   -o log4j-api.jar; \
    curl -fsSL "$B/org/apache/logging/log4j/log4j-core/$LVER/log4j-core-$LVER.jar" -o log4j-core.jar; \
    curl -fsSL "$B/commons-collections/commons-collections/$CCVER/commons-collections-$CCVER.jar" -o cc.jar

COPY Receiver.java .
RUN javac -cp log4j-api.jar:log4j-core.jar Receiver.java

EXPOSE 4560
# MITIGATE=1 turns on the serialization filter that blocks the bypass.
ENTRYPOINT ["sh","-c","JVMOPTS=; [ \"${MITIGATE:-0}\" = 1 ] && JVMOPTS=\"-Djdk.serialFilter=!java.rmi.MarshalledObject\"; exec java $JVMOPTS -cp .:log4j-api.jar:log4j-core.jar:cc.jar Receiver ${PORT:-4560}"]
