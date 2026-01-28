apiVersion: apps/v1
kind: Deployment
metadata:
  name: hsm
  labels:
    app: hsm
spec:
  replicas: 1
  selector:
    matchLabels:
      app: hsm
  template:
    metadata:
      labels:
        app: hsm
    spec:
      initContainers:
        - name: init-token
          image: ${actions.build.hsm.outputs.deployment-image-id}
          command:
            - sh
            - -c
            - |
              if [ -z "$(ls -A /var/lib/softhsm/tokens 2>/dev/null)" ]; then
                echo "Initializing SoftHSM2 token..."
                softhsm2-util --init-token --slot 0 --label "kels-hsm" --pin 1234 --so-pin 12345678
                echo "Token initialized."
              else
                echo "Token already exists, skipping initialization."
              fi
          volumeMounts:
            - name: hsm-tokens
              mountPath: /var/lib/softhsm/tokens
      containers:
        - name: hsm
          image: ${actions.build.hsm.outputs.deployment-image-id}
          ports:
            - containerPort: 80
              name: http
          env:
            - name: RUST_LOG
              value: "${var.rustLogLevel}"
            - name: SOFTHSM2_LIBRARY
              value: "/usr/lib/softhsm/libsofthsm2.so"
            - name: HSM_SLOT
              value: "0"
            - name: HSM_PIN
              value: "1234"
          volumeMounts:
            - name: hsm-tokens
              mountPath: /var/lib/softhsm/tokens
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
      volumes:
        - name: hsm-tokens
          persistentVolumeClaim:
            claimName: hsm-tokens-pvc

---

apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: hsm-tokens-pvc
  labels:
    app: hsm
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
  name: hsm
  labels:
    app: hsm
spec:
  type: ClusterIP
  ports:
    - port: ${var.hsm.port}
      targetPort: 80
      protocol: TCP
      name: http
  selector:
    app: hsm
