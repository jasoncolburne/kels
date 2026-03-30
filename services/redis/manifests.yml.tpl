apiVersion: v1
kind: ConfigMap
metadata:
  name: redis-config
  labels:
    app: redis
data:
  redis.conf: |
    # RDB persistence
    save 300 1
    save 60 100

    # Memory - volatile-lfu to match local W-TinyLFU eviction policy
    maxmemory 200mb
    maxmemory-policy volatile-lfu
    lfu-log-factor 10
    lfu-decay-time 1

    # ACL: KELS service
    user kels on #${var.redis.kelsPasswordHash} ~kels:kel:* ~kels:verified-peer:* %R~kels:gossip:ready &kel_updates +get +set +setex +del +publish +subscribe +ping

    # ACL: SADStore service
    user sadstore on #${var.redis.sadstorePasswordHash} ~kels:sad:* ~kels:verified-peer:* &sad_updates &sad_chain_updates +get +set +setex +del +publish +subscribe +ping

    # ACL: Gossip service
    user gossip on #${var.redis.gossipPasswordHash} ~kels:gossip:* ~kels:anti_entropy:* &kel_updates &sad_updates &sad_chain_updates +get +set +del +subscribe +hset +hgetall +ping

    # Disable default user
    user default off

---

apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: redis-data
  labels:
    app: redis
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 256Mi

---

apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  labels:
    app: redis
spec:
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
            - /etc/redis/redis.conf
          resources:
            requests:
              cpu: 25m
              memory: 64Mi
            limits:
              cpu: 750m
              memory: 512Mi
          livenessProbe:
            exec:
              command:
                - redis-cli
                - --user
                - kels
                - -a
                - "${var.redis.kelsPassword}"
                - --no-auth-warning
                - ping
            initialDelaySeconds: 2
            periodSeconds: 10
          readinessProbe:
            exec:
              command:
                - redis-cli
                - --user
                - kels
                - -a
                - "${var.redis.kelsPassword}"
                - --no-auth-warning
                - ping
            initialDelaySeconds: 2
            periodSeconds: 5
          volumeMounts:
            - name: redis-config
              mountPath: /etc/redis/redis.conf
              subPath: redis.conf
              readOnly: true
            - name: redis-data
              mountPath: /data
      volumes:
        - name: redis-config
          configMap:
            name: redis-config
        - name: redis-data
          persistentVolumeClaim:
            claimName: redis-data

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
