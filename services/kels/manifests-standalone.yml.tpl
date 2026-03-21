apiVersion: apps/v1
kind: Deployment
metadata:
  name: kels
  labels:
    app: kels
spec:
  replicas: 1
  selector:
    matchLabels:
      app: kels
  template:
    metadata:
      labels:
        app: kels
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
      containers:
        - name: kels
          image: ${actions.build.kels.outputs.deployment-image-id}
          ports:
            - containerPort: 80
              name: http
          env:
            - name: RUST_LOG
              value: "${var.rustLogLevel}"
            - name: DATABASE_URL
              value: "${var.kelsDatabaseUrl}"
            - name: KELS_MAX_SUBMISSIONS_PER_PREFIX_PER_MINUTE
              value: "${var.maxSubmissionsPerPrefixPerMinute}"
            - name: KELS_MAX_WRITES_PER_IP_PER_SECOND
              value: "${var.maxWritesPerIpPerSecond}"
            - name: KELS_IP_RATE_LIMIT_BURST
              value: "${var.ipRateLimitBurst}"
            - name: KELS_NONCE_WINDOW_SECS
              value: "${var.nonceWindowSecs}"
            - name: KELS_TEST_ENDPOINTS
              value: "${var.testEndpoints}"
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
              memory: 2Gi

---

apiVersion: v1
kind: Service
metadata:
  name: kels
  labels:
    app: kels
spec:
  type: ClusterIP
  ports:
    - port: ${var.kels.port}
      targetPort: 80
      protocol: TCP
      name: http
  selector:
    app: kels

---

apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: kels
  labels:
    app: kels
spec:
  ingressClassName: traefik
  rules:
    - host: kels.${environment.namespace}.kels
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: kels
                port:
                  number: ${var.kels.port}
