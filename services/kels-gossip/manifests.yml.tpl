apiVersion: apps/v1
kind: Deployment
metadata:
  name: kels-gossip
  labels:
    app: kels-gossip
spec:
  replicas: ${var.gossip.replicas}
  strategy:
    type: Recreate
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
        - name: wait-for-hsm
          image: busybox:1.36
          command:
            - sh
            - -c
            - |
              until nc -z ${var.hsm.host} ${var.hsm.port}; do
                echo "Waiting for HSM...";
                sleep 2;
              done;
              echo "HSM is ready!";
        - name: wait-for-identity
          image: busybox:1.36
          command:
            - sh
            - -c
            - |
              until nc -z ${var.identity.host} ${var.identity.port}; do
                echo "Waiting for identity...";
                sleep 2;
              done;
              echo "Identity is ready!";
      containers:
        - name: kels-gossip
          image: ${actions.build.kels-gossip.outputs.deployment-image-id}
          ports:
            - containerPort: 4001
              name: gossip
            - containerPort: ${var.gossip.httpPort}
              name: http
          env:
            - name: HTTP_LISTEN_HOST
              value: "${var.gossip.httpListenHost}"
            - name: HTTP_LISTEN_PORT
              value: "${var.gossip.httpPort}"
            - name: RUST_LOG
              value: "${var.rustLogLevel}"
            - name: NODE_ID
              value: "${environment.name}"
            - name: KELS_URL
              value: "${var.kels.url}"
            - name: KELS_ADVERTISE_URL
              value: "${var.kelsAdvertiseUrl}"
            - name: REDIS_URL
              value: "${var.redis.url}"
            - name: HSM_URL
              value: "${var.hsm.url}"
            - name: IDENTITY_URL
              value: "${var.identityUrl}"
            - name: REGISTRY_URL
              value: "${var.registryUrl}"
            - name: FEDERATION_REGISTRY_URLS
              value: "${var.federationRegistryUrls}"
            - name: GOSSIP_LISTEN_ADDR
              value: "${var.gossip.listenAddress}"
            - name: GOSSIP_ADVERTISE_ADDR
              value: "${var.gossipAdvertiseAddress}"
            - name: GOSSIP_TOPIC
              value: "${var.gossip.topic}"
            - name: ANTI_ENTROPY_INTERVAL_SECS
              value: "${var.gossipAntiEntropyIntervalSecs}"
          livenessProbe:
            httpGet:
              path: /healthz
              port: http
            initialDelaySeconds: 2
            periodSeconds: 10
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
      name: gossip
    - port: ${var.gossip.httpPort}
      targetPort: ${var.gossip.httpPort}
      protocol: TCP
      name: http
  selector:
    app: kels-gossip

