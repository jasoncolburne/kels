apiVersion: v1
kind: ConfigMap
metadata:
  name: postgres-init
  labels:
    app: postgres
data:
  init.sql: |
    -- Create databases only (schemas will be managed by SQLx migrations in each service)
    SELECT 'CREATE DATABASE kels' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'kels')\gexec
    SELECT 'CREATE DATABASE kels_gossip' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'kels_gossip')\gexec

---

apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-pvc
  labels:
    app: postgres
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi

---

apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  labels:
    app: postgres
spec:
  serviceName: postgres
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
        - name: postgres
          image: postgres:16-alpine
          ports:
            - containerPort: 5432
              name: postgres
          env:
            - name: POSTGRES_USER
              value: "${var.postgres.user}"
            - name: POSTGRES_PASSWORD
              value: "${var.postgres.password}"
            - name: POSTGRES_DB
              value: "postgres"
            - name: PGDATA
              value: "/var/lib/postgresql/data/pgdata"
          volumeMounts:
            - name: postgres-storage
              mountPath: /var/lib/postgresql/data
            - name: init-scripts
              mountPath: /docker-entrypoint-initdb.d
          resources:
            requests:
              cpu: 250m
              memory: 256Mi
            limits:
              cpu: 1000m
              memory: 1Gi
          livenessProbe:
            exec:
              command:
                - pg_isready
                - -U
                - ddi_admin
                - -d
                - postgres
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            exec:
              command:
                - pg_isready
                - -U
                - ddi_admin
                - -d
                - postgres
            initialDelaySeconds: 5
            periodSeconds: 5
      volumes:
        - name: postgres-storage
          persistentVolumeClaim:
            claimName: postgres-pvc
        - name: init-scripts
          configMap:
            name: postgres-init

---

apiVersion: v1
kind: Service
metadata:
  name: postgres
  labels:
    app: postgres
spec:
  type: ClusterIP
  ports:
    - port: 5432
      targetPort: 5432
      protocol: TCP
      name: postgres
  selector:
    app: postgres
