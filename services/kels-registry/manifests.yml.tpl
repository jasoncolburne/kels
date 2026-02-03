apiVersion: apps/v1
kind: Deployment
metadata:
  name: kels-registry
  labels:
    app: kels-registry
spec:
  replicas: ${var.registry.replicas}
  selector:
    matchLabels:
      app: kels-registry
  template:
    metadata:
      labels:
        app: kels-registry
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
              echo "Postgres is ready!";
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
        - name: wait-for-identity
          image: busybox:1.36
          command:
            - sh
            - -c
            - |
              until nc -z ${var.identity.host} ${var.identity.port}; do
                echo "Waiting for identity service...";
                sleep 2;
              done;
              echo "Identity service is ready!";
      containers:
        - name: kels-registry
          image: ${actions.build.kels-registry.outputs.deployment-image-id}
          ports:
            - containerPort: 80
              name: http
          env:
            - name: RUST_LOG
              value: "${var.rustLogLevel}"
            - name: REDIS_URL
              value: "${var.redis.url}"
            - name: DATABASE_URL
              value: "${var.kelsRegistryDatabaseUrl}"
            - name: IDENTITY_URL
              value: "${var.identityUrl}"
            - name: HEARTBEAT_TIMEOUT_SECS
              value: "${var.registry.heartbeatTimeoutSecs}"
            - name: FEDERATION_SELF_PREFIX
              value: "${var.federationSelfPrefix}"
            - name: FEDERATION_MEMBERS
              value: "${var.federationMembers}"
          livenessProbe:
            httpGet:
              path: /health
              port: 80
            initialDelaySeconds: 10
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /health
              port: 80
            initialDelaySeconds: 5
            periodSeconds: 5
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
            limits:
              cpu: 500m
              memory: 256Mi

---

apiVersion: v1
kind: Service
metadata:
  name: kels-registry
  labels:
    app: kels-registry
spec:
  type: ClusterIP
  ports:
    - port: ${var.registry.port}
      targetPort: 80
      protocol: TCP
      name: http
  selector:
    app: kels-registry

---

apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: kels-registry
  labels:
    app: kels-registry
spec:
  ingressClassName: nginx
  rules:
    - host: kels-registry.${environment.namespace}.local
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: kels-registry
                port:
                  number: ${var.registry.port}
