# Blue Team jump box: SSH access for log forensics on custom port 2275.
FROM alpine:3.20

RUN apk add --no-cache openssh bash shadow \
  && ssh-keygen -A \
  && adduser -D -s /bin/bash analyst \
  && echo "analyst:blue_team_rocks" | chpasswd \
  && mkdir -p /opt/admin/logs \
  && chown -R analyst:analyst /opt/admin/logs \
  && sed -i 's/#Port 22/Port 2275/' /etc/ssh/sshd_config \
  && sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
  && sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 2275

CMD ["/usr/sbin/sshd", "-D", "-e"]
