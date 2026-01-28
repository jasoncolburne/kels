apiVersion: apps/v1
kind: Deployment
metadata:
  name: identity
  labels:
    app: identity
spec:
  replicas: 1
  selector:
    matchLabels:
      app: identity
  template:
    metadata:
      labels:
        app: identity
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
        - name: wait-for-hsm
          image: busybox:1.36
          command:
            - sh
            - -c
            - |
              until nc -z hsm ${var.hsm.port}; do
                echo "Waiting for hsm...";
                sleep 2;
              done;
              echo "HSM is ready!";
      containers:
        - name: identity
          image: ${actions.build.identity.outputs.deployment-image-id}
          ports:
            - containerPort: 80
              name: http
          env:
            - name: RUST_LOG
              value: "${var.rustLogLevel}"
            - name: KEY_HANDLE_PREFIX
              value: "${var.identityKeyHandlePrefix}"
            - name: DATABASE_URL
              value: "${var.identityDatabaseUrl}"
            - name: HSM_URL
              value: "${var.hsm.url}"
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
              cpu: 500m
              memory: 512Mi

---

apiVersion: v1
kind: Service
metadata:
  name: identity
  labels:
    app: identity
spec:
  type: ClusterIP
  ports:
    - port: ${var.identity.port}
      targetPort: 80
      protocol: TCP
      name: http
  selector:
    app: identity
