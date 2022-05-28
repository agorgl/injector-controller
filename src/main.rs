use anyhow::{Context, Result};
use json_patch::PatchOperation;
use k8s_openapi::api::core::v1::{
    Container, EmptyDirVolumeSource, Pod, SecretVolumeSource, Volume, VolumeMount,
};
use kube::core::{
    admission::{AdmissionRequest, AdmissionResponse, AdmissionReview, Operation},
    DynamicObject, ResourceExt,
};
use std::{convert::Infallible, error::Error};
use tracing::*;
use warp::{reply, Filter, Reply};

fn patch_pod(pod: &mut Pod, tls_secret: &str, java_home: Option<&String>) -> Result<()> {
    let spec = pod
        .spec
        .as_mut()
        .context("pod definition must have a spec")?;
    let volumes = spec.volumes.get_or_insert(vec![]);
    let init_containters = spec.init_containers.get_or_insert(vec![]);

    // Add volumes
    let mut cert_volumes = vec![
        Volume {
            name: tls_secret.into(),
            secret: Some(SecretVolumeSource {
                secret_name: Some(tls_secret.into()),
                ..Default::default()
            }),
            ..Default::default()
        },
        Volume {
            name: "certs".into(),
            empty_dir: Some(EmptyDirVolumeSource::default()),
            ..Default::default()
        },
    ];
    volumes.append(&mut cert_volumes);

    // Add volume mounts
    let containers_iter = spec.containers.iter_mut();
    let init_containters_iter = init_containters.iter_mut();
    for c in containers_iter.chain(init_containters_iter) {
        let mounts = c.volume_mounts.get_or_insert(vec![]);
        let mut cert_mounts = vec![VolumeMount {
            name: "certs".into(),
            read_only: Some(false),
            mount_path: "/etc/ssl/certs".into(),
            ..Default::default()
        }];
        if let Some(java_home) = java_home {
            let java_home = if java_home == "default" { "/opt/java/openjdk" } else { java_home };
            cert_mounts.push(
                VolumeMount {
                    name: "certs".into(),
                    read_only: Some(false),
                    sub_path: Some("java/cacerts".into()),
                    mount_path: format!("{java_home}/lib/security/cacerts"),
                    ..Default::default()
                }
            );
        }
        mounts.append(&mut cert_mounts);
    }

    // Add sidecar container
    let sidecar_container = Container {
        name: "inject-certificate".into(),
        image: Some("alpine".into()),
        command: Some(vec![
            "/bin/sh",
            "-c",
            "(apk add -U ca-certificates java-cacerts && update-ca-certificates); cp -r /etc/ssl/certs/. /certificates"
        ].into_iter().map(|s| s.to_owned()).collect()),
        volume_mounts: Some(vec![
            VolumeMount {
                name: tls_secret.into(),
                read_only: Some(true),
                sub_path: Some("tls.crt".into()),
                mount_path: "/usr/local/share/ca-certificates/{tls_secret}.crt".into(),
                ..Default::default()
            },
            VolumeMount {
                name: "certs".into(),
                read_only: Some(false),
                mount_path: "/certificates".into(),
                ..Default::default()
            },
        ]),
        ..Default::default()
    };
    init_containters.insert(0, sidecar_container);

    Ok(())
}

fn make_patches(pod: &Pod) -> Result<Vec<PatchOperation>> {
    let spec = pod
        .spec
        .as_ref()
        .context("pod definition must have a spec")?;

    let patches = vec![
        json_patch::PatchOperation::Replace(json_patch::ReplaceOperation {
            path: "/spec/volumes".into(),
            value: serde_json::to_value(&spec.volumes).context("could not create volumes patch")?,
        }),
        json_patch::PatchOperation::Replace(json_patch::ReplaceOperation {
            path: "/spec/containers".into(),
            value: serde_json::to_value(&spec.containers)
                .context("could not create volumes patch")?,
        }),
        json_patch::PatchOperation::Replace(json_patch::ReplaceOperation {
            path: "/spec/initContainers".into(),
            value: serde_json::to_value(&spec.init_containers)
                .context("could not create volumes patch")?,
        }),
    ];

    Ok(patches)
}

// The main handler and core business logic, failures here implies rejected applies
fn mutate(
    res: AdmissionResponse,
    obj: &DynamicObject,
    oper: &Operation,
) -> Result<AdmissionResponse, Box<dyn Error>> {
    // Skip requests missing types
    let types = match obj.types.as_ref() {
        Some(t) => t,
        None => return Ok(res),
    };

    // Process only pod creations
    if types.kind == "Pod" && *oper == Operation::Create {
        // If the resource contains annotation, process it
        if let Some(tls_secret) = obj.annotations().get("injector/certificate") {
            // Get optional java home path
            let java_path = obj.annotations().get("injector/java-home");
            // Deserialize object as a pod
            let mut pod: Pod = serde_json::from_value(obj.data.clone())
                .context("could not deserialize pod object")?;
            // Patch the resource
            info!("patching: Pod with tls secret {tls_secret}");
            patch_pod(&mut pod, &tls_secret, java_path)?;
            // Make json patch list
            let patches = make_patches(&pod)?;
            // Return admission response with patches
            return Ok(res.with_patch(json_patch::Patch(patches))?);
        }
    }

    Ok(res)
}

// A general /mutate handler, handling errors from the underlying business logic
async fn mutate_handler(body: AdmissionReview<DynamicObject>) -> Result<impl Reply, Infallible> {
    // Parse incoming webhook AdmissionRequest first
    let req: AdmissionRequest<_> = match body.try_into() {
        Ok(req) => req,
        Err(err) => {
            error!("invalid request: {}", err.to_string());
            return Ok(reply::json(
                &AdmissionResponse::invalid(err.to_string()).into_review(),
            ));
        }
    };

    // Then construct a AdmissionResponse
    let mut res = AdmissionResponse::from(&req);
    // req.Object always exists for us, but could be None if extending to DELETE events
    if let Some(obj) = req.object {
        let name = obj
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get("app.kubernetes.io/name").cloned())
            .unwrap_or("<NAME_MISSING>".to_owned());
        res = match mutate(res.clone(), &obj, &req.operation) {
            Ok(res) => {
                info!("accepted: {:?} on {}", req.operation, name);
                res
            }
            Err(err) => {
                warn!("denied: {:?} on {} ({})", req.operation, name, err);
                res.deny(err.to_string())
            }
        };
    };
    // Wrap the AdmissionResponse wrapped in an AdmissionReview
    Ok(reply::json(&res.into_review()))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("Starting injector controller");

    let routes = warp::path("mutate")
        .and(warp::body::json())
        .and_then(mutate_handler)
        .with(warp::trace::request());

    // You must generate a certificate for the service / url,
    // encode the CA in the MutatingWebhookConfiguration, and terminate TLS here
    //let addr = format!("{}:8443", std::env::var("ADMISSION_PRIVATE_IP").unwrap());
    warp::serve(warp::post().and(routes))
        .tls()
        .cert_path("/tls/tls.crt")
        .key_path("/tls/tls.key")
        .run(([0, 0, 0, 0], 8443)) // in-cluster
        //.run(addr.parse::<std::net::SocketAddr>().unwrap()) // local-dev
        .await;
}
