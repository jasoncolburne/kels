apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: redis-pvc
  labels:
    app: redis
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
  name: redis
  labels:
    app: redis
spec:
  serviceName: redis
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
        - name: redis
          image: redis:7-alpine
          ports:
            - containerPort: ${var.redis.port}
              name: redis
          args:
            - redis-server
            - --appendonly
            - "no"
            - --appendfsync
            - "everysec"
            - --maxmemory
            - "200mb"
            - --maxmemory-policy
            - "allkeys-lru"
          volumeMounts:
            - name: redis-storage
              mountPath: /data
          resources:
            requests:
              cpu: 100m
              memory: 64Mi
            limits:
              cpu: 750m
              memory: 512Mi
          livenessProbe:
            exec:
              command:
                - redis-cli
                - ping
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            exec:
              command:
                - redis-cli
                - ping
            initialDelaySeconds: 5
            periodSeconds: 5
      volumes:
        - name: redis-storage
          persistentVolumeClaim:
            claimName: redis-pvc

---

apiVersion: v1
kind: Service
metadata:
  name: redis
  labels:
    app: redis
spec:
  type: ClusterIP
  ports:
    - port: ${var.redis.port}
      targetPort: ${var.redis.port}
      protocol: TCP
      name: redis
  selector:
    app: redis
