apiVersion: v1
kind: Pod
metadata:
  name: test-client
  labels:
    app: test-client
spec:
  terminationGracePeriodSeconds: 1
  containers:
    - name: test-client
      image: ${actions.build.test-client.outputs.deployment-image-id}
      command: ["/bin/sh", "-c"]
      args: ["trap 'exit 0' SIGTERM; sleep infinity & wait $!"]
      resources:
        requests:
          cpu: 500m
          memory: 256Mi
        limits:
          cpu: 8000m
          memory: 1Gi
      env:
