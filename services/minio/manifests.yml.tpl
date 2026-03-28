apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: minio-pvc
  labels:
    app: minio
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
  name: minio
  labels:
    app: minio
spec:
  serviceName: minio
  replicas: 1
  selector:
    matchLabels:
      app: minio
  template:
    metadata:
      labels:
        app: minio
    spec:
      containers:
        - name: minio
          image: minio/minio:latest
          args:
            - server
            - /data
          ports:
            - containerPort: 9000
              name: s3
          env:
            - name: MINIO_ROOT_USER
              value: "${var.minio.accessKey}"
            - name: MINIO_ROOT_PASSWORD
              value: "${var.minio.secretKey}"
          volumeMounts:
            - name: minio-storage
              mountPath: /data
          resources:
            requests:
              cpu: 25m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
          livenessProbe:
            httpGet:
              path: /minio/health/live
              port: 9000
            initialDelaySeconds: 5
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /minio/health/ready
              port: 9000
            initialDelaySeconds: 5
            periodSeconds: 5
      volumes:
        - name: minio-storage
          persistentVolumeClaim:
            claimName: minio-pvc

---

apiVersion: v1
kind: Service
metadata:
  name: minio
  labels:
    app: minio
spec:
  type: ClusterIP
  ports:
    - port: ${var.minio.port}
      targetPort: 9000
      protocol: TCP
      name: s3
  selector:
    app: minio
