apiVersion: apps/v1
kind: Deployment
metadata:
  name: kels
  labels:
    app: kels
spec:
  replicas: ${var.kels.replicas}
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
            - name: REDIS_URL
              value: "${var.redis.url}"
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
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 1000m
              memory: 512Mi

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
  ingressClassName: nginx
  rules:
    - host: kels.${environment.namespace}.local
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: kels
                port:
                  number: ${var.kels.port}
