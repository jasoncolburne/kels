apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: objects-pvc
  labels:
    app: objects
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi

---

apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: objects
  labels:
    app: objects
spec:
  serviceName: objects
  replicas: 1
  selector:
    matchLabels:
      app: objects
  template:
    metadata:
      labels:
        app: objects
    spec:
      # RustFS runs as non-root UID 10001; fsGroup applies that group to
      # the mounted PVC so the process can write to /data.
      securityContext:
        fsGroup: 10001
      containers:
        - name: objects
          image: rustfs/rustfs:latest
          ports:
            - containerPort: 9000
              name: s3
            - containerPort: 9001
              name: console
          env:
            - name: RUSTFS_VOLUMES
              value: "/data"
            - name: RUSTFS_ADDRESS
              value: "0.0.0.0:9000"
            - name: RUSTFS_CONSOLE_ADDRESS
              value: "0.0.0.0:9001"
            - name: RUSTFS_ACCESS_KEY
              value: "${var.objects.accessKey}"
            - name: RUSTFS_SECRET_KEY
              value: "${var.objects.secretKey}"
            - name: RUSTFS_BUFFER_PROFILE
              value: "WebWorkload"
          volumeMounts:
            - name: objects-storage
              mountPath: /data
          resources:
            requests:
              cpu: 25m
              memory: 128Mi
            limits:
              cpu: 2000m
              memory: 1Gi
          livenessProbe:
            httpGet:
              path: /health
              port: 9000
            initialDelaySeconds: 5
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /health
              port: 9000
            initialDelaySeconds: 5
            periodSeconds: 5
      volumes:
        - name: objects-storage
          persistentVolumeClaim:
            claimName: objects-pvc

---

apiVersion: v1
kind: Service
metadata:
  name: objects
  labels:
    app: objects
spec:
  type: ClusterIP
  ports:
    - port: ${var.objects.port}
      targetPort: 9000
      protocol: TCP
      name: s3
  selector:
    app: objects
