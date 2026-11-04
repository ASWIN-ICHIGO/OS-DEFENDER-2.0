use os_defender_core::ipc::{
    IpcListener, IpcRequest, IpcResponse, IpcStream,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::test]
async fn transport_connect_and_exchange() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = dir.path().join("test.sock").to_string_lossy().into_owned();

    let ep_clone = endpoint.clone();
    let server = tokio::spawn(async move {
        let listener = IpcListener::bind(&ep_clone).await.unwrap();
        let stream = listener.accept().await.unwrap();
        let (reader, mut writer) = tokio::io::split(stream);
        let mut lines = BufReader::new(reader).lines();

        let line = lines.next_line().await.unwrap().unwrap();
        let req: IpcRequest = serde_json::from_str(&line).unwrap();
        assert!(matches!(req, IpcRequest::Status));

        let resp = IpcResponse::Ok;
        let mut json = serde_json::to_string(&resp).unwrap();
        json.push('\n');
        writer.write_all(json.as_bytes()).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let stream = IpcStream::connect(&endpoint).await.unwrap();
    let (reader, mut writer) = tokio::io::split(stream);

    let req = IpcRequest::Status;
    let mut json = serde_json::to_string(&req).unwrap();
    json.push('\n');
    writer.write_all(json.as_bytes()).await.unwrap();

    let mut lines = BufReader::new(reader).lines();
    let line = lines.next_line().await.unwrap().unwrap();
    let resp: IpcResponse = serde_json::from_str(&line).unwrap();
    assert!(matches!(resp, IpcResponse::Ok));

    server.await.unwrap();
}

#[tokio::test]
async fn transport_multiple_clients() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = dir.path().join("multi.sock").to_string_lossy().into_owned();

    let ep_clone = endpoint.clone();
    let server = tokio::spawn(async move {
        let listener = IpcListener::bind(&ep_clone).await.unwrap();
        for _ in 0..3 {
            let stream = listener.accept().await.unwrap();
            let (reader, mut writer) = tokio::io::split(stream);
            let mut lines = BufReader::new(reader).lines();
            let line = lines.next_line().await.unwrap().unwrap();
            let _req: IpcRequest = serde_json::from_str(&line).unwrap();

            let resp = IpcResponse::Ok;
            let mut json = serde_json::to_string(&resp).unwrap();
            json.push('\n');
            writer.write_all(json.as_bytes()).await.unwrap();
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    for _ in 0..3 {
        let stream = IpcStream::connect(&endpoint).await.unwrap();
        let (reader, mut writer) = tokio::io::split(stream);

        let req = IpcRequest::Status;
        let mut json = serde_json::to_string(&req).unwrap();
        json.push('\n');
        writer.write_all(json.as_bytes()).await.unwrap();

        let mut lines = BufReader::new(reader).lines();
        let line = lines.next_line().await.unwrap().unwrap();
        let resp: IpcResponse = serde_json::from_str(&line).unwrap();
        assert!(matches!(resp, IpcResponse::Ok));
    }

    server.await.unwrap();
}

#[tokio::test]
async fn transport_connect_refused() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = dir.path().join("nonexistent.sock").to_string_lossy().into_owned();
    let result = IpcStream::connect(&endpoint).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn transport_json_protocol_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = dir.path().join("proto.sock").to_string_lossy().into_owned();

    let requests = vec![
        IpcRequest::Status,
        IpcRequest::GetEvents { limit: 10 },
        IpcRequest::GetHealth,
        IpcRequest::GetAuditLog { limit: 5 },
        IpcRequest::GetPolicyMode,
        IpcRequest::GetAiStatus,
        IpcRequest::GetPosture,
        IpcRequest::GetPersistence,
        IpcRequest::VerifyIntegrity,
        IpcRequest::VerifyAuditChain,
    ];

    let ep_clone = endpoint.clone();
    let count = requests.len();
    let server = tokio::spawn(async move {
        let listener = IpcListener::bind(&ep_clone).await.unwrap();
        let stream = listener.accept().await.unwrap();
        let (reader, mut writer) = tokio::io::split(stream);
        let mut lines = BufReader::new(reader).lines();

        for _ in 0..count {
            let line = lines.next_line().await.unwrap().unwrap();
            let _req: IpcRequest = serde_json::from_str(&line).unwrap();
            let resp = IpcResponse::Ok;
            let mut json = serde_json::to_string(&resp).unwrap();
            json.push('\n');
            writer.write_all(json.as_bytes()).await.unwrap();
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let stream = IpcStream::connect(&endpoint).await.unwrap();
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    for req in &requests {
        let mut json = serde_json::to_string(req).unwrap();
        json.push('\n');
        writer.write_all(json.as_bytes()).await.unwrap();

        let line = lines.next_line().await.unwrap().unwrap();
        let resp: IpcResponse = serde_json::from_str(&line).unwrap();
        assert!(matches!(resp, IpcResponse::Ok));
    }

    server.await.unwrap();
}

#[tokio::test]
async fn transport_client_disconnect_handled() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = dir.path().join("disc.sock").to_string_lossy().into_owned();

    let ep_clone = endpoint.clone();
    let server = tokio::spawn(async move {
        let listener = IpcListener::bind(&ep_clone).await.unwrap();
        let stream = listener.accept().await.unwrap();
        let (reader, _writer) = tokio::io::split(stream);
        let mut lines = BufReader::new(reader).lines();
        // Client connects then drops — next_line returns None
        let result = lines.next_line().await.unwrap();
        assert!(result.is_none());
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    {
        let _stream = IpcStream::connect(&endpoint).await.unwrap();
        // drop immediately
    }

    server.await.unwrap();
}

#[tokio::test]
async fn transport_error_response_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = dir.path().join("err.sock").to_string_lossy().into_owned();

    let ep_clone = endpoint.clone();
    let server = tokio::spawn(async move {
        let listener = IpcListener::bind(&ep_clone).await.unwrap();
        let stream = listener.accept().await.unwrap();
        let (reader, mut writer) = tokio::io::split(stream);
        let mut lines = BufReader::new(reader).lines();
        let _line = lines.next_line().await.unwrap().unwrap();

        let resp = IpcResponse::Error {
            message: "test error message".to_string(),
        };
        let mut json = serde_json::to_string(&resp).unwrap();
        json.push('\n');
        writer.write_all(json.as_bytes()).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let stream = IpcStream::connect(&endpoint).await.unwrap();
    let (reader, mut writer) = tokio::io::split(stream);
    let mut json = serde_json::to_string(&IpcRequest::Status).unwrap();
    json.push('\n');
    writer.write_all(json.as_bytes()).await.unwrap();

    let mut lines = BufReader::new(reader).lines();
    let line = lines.next_line().await.unwrap().unwrap();
    let resp: IpcResponse = serde_json::from_str(&line).unwrap();
    match resp {
        IpcResponse::Error { message } => assert_eq!(message, "test error message"),
        _ => panic!("expected Error response"),
    }

    server.await.unwrap();
}
