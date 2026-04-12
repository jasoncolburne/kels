apiVersion: apps/v1
kind: Deployment
metadata:
  name: mail
  labels:
    app: mail
spec:
  replicas: ${var.mail.replicas}
  selector:
    matchLabels:
      app: mail
  template:
    metadata:
      labels:
        app: mail
    spec:
      initContainers:
        - name: wait-for-postgres
          image: busybox:1.36
          command:
            - sh
            - -c
            - |
              until nc -z postgres 5432; do
                echo "Waiting for postgres...";
                sleep 2;
              done;
              echo "PostgreSQL is ready!";
        - name: wait-for-minio
          image: busybox:1.36
          command:
            - sh
            - -c
            - |
              until nc -z minio 9000; do
                echo "Waiting for MinIO...";
                sleep 2;
              done;
              echo "MinIO is ready!";
        - name: wait-for-identity
          image: busybox:1.36
          command:
            - sh
            - -c
            - |
              until nc -z identity 80; do
                echo "Waiting for identity...";
                sleep 2;
              done;
              echo "Identity is ready!";
        - name: wait-for-redis
          image: busybox:1.36
          command:
            - sh
            - -c
            - |
              until nc -z redis 6379; do
                echo "Waiting for redis...";
                sleep 2;
              done;
              echo "Redis is ready!";
      containers:
        - name: mail
          image: ${actions.build.mail.outputs.deployment-image-id}
          ports:
            - containerPort: 80
              name: http
          env:
            - name: RUST_LOG
              value: "${var.rustLogLevel}"
            - name: PORT
              value: "80"
            - name: DATABASE_URL
              value: "${var.mailDatabaseUrl}"
            - name: REDIS_URL
              value: "${var.redis.mailUrl}"
            - name: KELS_URL
              value: "${var.kels.url}"
            - name: IDENTITY_URL
              value: "${var.identity.url}"
            - name: MINIO_ENDPOINT
              value: "http://${var.minio.host}:${var.minio.port}"
            - name: MINIO_REGION
              value: "${var.minio.region}"
            - name: MINIO_ACCESS_KEY
              value: "${var.minio.accessKey}"
            - name: MINIO_SECRET_KEY
              value: "${var.minio.secretKey}"
            - name: KELS_MAIL_BUCKET
              value: "${var.mail.bucket}"
            - name: MAIL_MAX_MESSAGES_PER_SENDER_PER_DAY
              value: "${var.mail.maxMessagesPerSenderPerDay}"
            - name: MAIL_MAX_WRITES_PER_IP_PER_SECOND
              value: "${var.mail.maxWritesPerIpPerSecond}"
            - name: MAIL_IP_RATE_LIMIT_BURST
              value: "${var.mail.ipRateLimitBurst}"
            - name: MAIL_MAX_INBOX_SIZE
              value: "${var.mail.maxInboxSize}"
            - name: MAIL_MAX_STORAGE_PER_RECIPIENT_MB
              value: "${var.mail.maxStoragePerRecipientMb}"
            - name: MAIL_MAX_BLOB_SIZE_BYTES
              value: "${var.mail.maxBlobSizeBytes}"
            - name: MAIL_MESSAGE_TTL_DAYS
              value: "${var.mail.messageTtlDays}"
          livenessProbe:
            httpGet:
              path: /health
              port: 80
            initialDelaySeconds: 2
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /health
              port: 80
            initialDelaySeconds: 2
            periodSeconds: 5
          resources:
            requests:
              cpu: 25m
              memory: 128Mi
            limits:
              cpu: 1000m
              memory: 1Gi

---

apiVersion: v1
kind: Service
metadata:
  name: mail
  labels:
    app: mail
spec:
  type: ClusterIP
  ports:
    - port: ${var.mail.port}
      targetPort: 80
      protocol: TCP
      name: http
  selector:
    app: mail

---

apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: mail
  labels:
    app: mail
spec:
  ingressClassName: traefik
  rules:
    - host: mail.${environment.name}.kels
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: mail
                port:
                  number: ${var.mail.port}
