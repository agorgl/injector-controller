# injector-controller

A kubernetes controller for injecting tls certificates written in Rust.

## Using

To inject a tls certificate from a secret, annotate the pod template with `injector/certificate` annotation,
passing the secret that holds the tls certificate:
```
kubectl patch deployment sample -p '{"spec":{"template":{"metadata":{"annotations":{"injector/certificate":"some-tls"}}}}}'
```

To mount a patched cacerts file to be used by jdk based images, annotate the pod template with `injector/java-home` annotation,
passing the path to $JAVA_HOME inside the container image or `default` to default to `/opt/java/openjdk`:
```
kubectl patch deployment sample -p '{"spec":{"template":{"metadata":{"annotations":{"injector/java-home":"default"}}}}}'
```
