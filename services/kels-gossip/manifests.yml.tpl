apiVersion: apps/v1
kind: Deployment
metadata:
  name: kels-gossip
  labels:
    app: kels-gossip
spec:
  replicas: ${var.gossip.replicas}
  selector:
    matchLabels:
      app: kels-gossip
  template:
    metadata:
      labels:
        app: kels-gossip
    spec:
      initContainers:
        - name: wait-for-kels
          image: busybox:1.36
          command:
            - sh
            - -c
            - |
              until nc -z kels 80; do
                echo "Waiting for kels...";
                sleep 2;
              done;
              echo "KELS is ready!";
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
        - name: kels-gossip
          image: ${actions.build.kels-gossip.outputs.deployment-image-id}
          ports:
            - containerPort: 4001
              name: libp2p
          env:
            - name: RUST_LOG
              value: "${var.rustLogLevel}"
            - name: KELS_URL
              value: "${var.kels.url}"
            - name: REDIS_URL
              value: "${var.redis.url}"
            - name: GOSSIP_LISTEN_ADDR
              value: "/ip4/0.0.0.0/tcp/${var.gossip.port}"
            - name: GOSSIP_BOOTSTRAP_PEERS
              value: "${var.gossip.bootstrapPeers}"
            - name: GOSSIP_TOPIC
              value: "${var.gossip.topic}"
            - name: GOSSIP_TEST_PROPAGATION_DELAY_MS
              value: "${var.gossip.testPropagationDelayMs}"
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
  name: kels-gossip
  labels:
    app: kels-gossip
spec:
  type: ClusterIP
  ports:
    - port: ${var.gossip.port}
      targetPort: 4001
      protocol: TCP
      name: libp2p
  selector:
    app: kels-gossip

---

# Headless service for peer discovery
apiVersion: v1
kind: Service
metadata:
  name: kels-gossip-headless
  labels:
    app: kels-gossip
spec:
  clusterIP: None
  ports:
    - port: ${var.gossip.port}
      targetPort: 4001
      protocol: TCP
      name: libp2p
  selector:
    app: kels-gossip
