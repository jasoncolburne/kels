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
            - name: PKCS11_LIBRARY
              value: "${var.identity.pkcs11Library}"
            - name: KELS_HSM_DATA_DIR
              value: "${var.identity.hsmDataDir}"
            - name: HSM_PIN
              value: "${var.identity.hsmPin}"
            - name: NEXT_SIGNING_ALGORITHM
              value: "${var.identity.signingAlgorithm}"
            - name: NEXT_RECOVERY_ALGORITHM
              value: "${var.identity.recoveryAlgorithm}"
            - name: KEL_FORWARD_URL
              value: "${var.kelForwardUrl}"
            - name: KEL_FORWARD_PATH_PREFIX
              value: "${var.kelForwardPathPrefix}"
          volumeMounts:
            - name: hsm-data
              mountPath: /data/hsm
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
              cpu: 500m
              memory: 512Mi
      volumes:
        - name: hsm-data
          persistentVolumeClaim:
            claimName: hsm-data

---

apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: hsm-data
  labels:
    app: identity
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 100Mi

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
