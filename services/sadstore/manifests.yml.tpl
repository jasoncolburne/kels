apiVersion: apps/v1
kind: Deployment
metadata:
  name: sadstore
  labels:
    app: sadstore
spec:
  replicas: ${var.sadstore.replicas}
  selector:
    matchLabels:
      app: sadstore
  template:
    metadata:
      labels:
        app: sadstore
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
        - name: wait-for-objects
          image: busybox:1.36
          command:
            - sh
            - -c
            - |
              until nc -z objects 9000; do
                echo "Waiting for object store...";
                sleep 2;
              done;
              echo "Object store is ready!";
      containers:
        - name: sadstore
          image: ${actions.build.sadstore.outputs.deployment-image-id}
          ports:
            - containerPort: 80
              name: http
          env:
            - name: RUST_LOG
              value: "${var.rustLogLevel}"
            - name: PORT
              value: "80"
            - name: DATABASE_URL
              value: "${var.sadstoreDatabaseUrl}"
            - name: REDIS_URL
              value: "${var.redisUrl}"
            - name: KELS_URL
              value: "${var.kels.url}"
            - name: OBJECTS_ENDPOINT
              value: "http://${var.objects.host}:${var.objects.port}"
            - name: OBJECTS_REGION
              value: "${var.objects.region}"
            - name: OBJECTS_ACCESS_KEY
              value: "${var.objects.accessKey}"
            - name: OBJECTS_SECRET_KEY
              value: "${var.objects.secretKey}"
            - name: KELS_SAD_BUCKET
              value: "${var.sadstore.bucket}"
            - name: SADSTORE_MAX_SEL_EVENTS_PER_PREFIX_PER_DAY
              value: "${var.sadstore.maxSelEventsPerPrefixPerDay}"
            - name: SADSTORE_MAX_IEL_EVENTS_PER_PREFIX_PER_DAY
              value: "${var.sadstore.maxIelEventsPerPrefixPerDay}"
            - name: SADSTORE_MAX_WRITES_PER_IP_PER_SECOND
              value: "${var.sadstore.maxWritesPerIpPerSecond}"
            - name: SADSTORE_IP_RATE_LIMIT_BURST
              value: "${var.sadstore.ipRateLimitBurst}"
            - name: SADSTORE_MAX_OBJECT_SIZE
              value: "${var.sadstore.maxObjectSize}"
            - name: FEDERATION_REGISTRY_URLS
              value: "${var.federationRegistryUrls}"
            - name: KELS_TEST_ENDPOINTS
              value: "${var.kels.testEndpoints}"
          livenessProbe:
            httpGet:
              path: /health
              port: 80
            initialDelaySeconds: 2
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
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
  name: sadstore
  labels:
    app: sadstore
spec:
  type: ClusterIP
  ports:
    - port: ${var.sadstore.port}
      targetPort: 80
      protocol: TCP
      name: http
  selector:
    app: sadstore

---

apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: sadstore
  labels:
    app: sadstore
spec:
  ingressClassName: traefik
  rules:
    - host: sadstore.${environment.name}.kels
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: sadstore
                port:
                  number: ${var.sadstore.port}
