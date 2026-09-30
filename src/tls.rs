use crate::secret::ShareKey;
use anyhow::Result;
use openssl::dh::Dh;
use openssl::error::ErrorStack;
use openssl::ssl::{
    SslAcceptor, SslConnector, SslContextBuilder, SslMethod, SslStream, SslVerifyMode, SslVersion,
};
use std::io::{Read, Write};
use std::net::TcpStream;

pub const LEGACY_PSK_CIPHERS: &str = "DHE-PSK-AES128-GCM-SHA256:DHE-PSK-AES256-GCM-SHA384";

pub fn accept_psk(stream: TcpStream, key: &ShareKey) -> Result<SslStream<TcpStream>> {
    accept_psk_material(stream, &key.tls_identity(), &key.tls_psk()?)
}

pub fn accept_psk_material(
    stream: TcpStream,
    identity: &str,
    psk: &[u8],
) -> Result<SslStream<TcpStream>> {
    let acceptor = server_acceptor(identity, psk)?;
    acceptor.accept(stream).map_err(|error| match error {
        openssl::ssl::HandshakeError::SetupFailure(error) => error.into(),
        openssl::ssl::HandshakeError::Failure(mid) => mid.into_error().into(),
        openssl::ssl::HandshakeError::WouldBlock(_) => {
            anyhow::anyhow!("TLS-PSK handshake would block")
        }
    })
}

pub fn connect_psk(stream: TcpStream, key: &ShareKey) -> Result<SslStream<TcpStream>> {
    connect_psk_material(stream, &key.tls_identity(), &key.tls_psk()?)
}

pub fn connect_psk_material(
    stream: TcpStream,
    identity: &str,
    psk: &[u8],
) -> Result<SslStream<TcpStream>> {
    let connector = client_connector(identity, psk)?;
    let configuration = connector
        .configure()?
        .use_server_name_indication(false)
        .verify_hostname(false);
    configuration
        .into_ssl("127.0.0.1")?
        .connect(stream)
        .map_err(|error| match error {
            openssl::ssl::HandshakeError::SetupFailure(error) => error.into(),
            openssl::ssl::HandshakeError::Failure(mid) => mid.into_error().into(),
            openssl::ssl::HandshakeError::WouldBlock(_) => {
                anyhow::anyhow!("TLS-PSK handshake would block")
            }
        })
}

fn server_acceptor(identity: &str, psk: &[u8]) -> Result<openssl::ssl::SslAcceptor> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    configure_context(&mut builder)?;
    let expected_identity = identity.as_bytes().to_vec();
    let psk = psk.to_vec();
    builder.set_psk_server_callback(move |_, identity, output| {
        let identity = identity.unwrap_or_default();
        if identity != expected_identity {
            return Err(ErrorStack::get());
        }
        if output.len() < psk.len() {
            return Err(ErrorStack::get());
        }
        output[..psk.len()].copy_from_slice(&psk);
        Ok(psk.len())
    });
    Ok(builder.build())
}

fn client_connector(identity: &str, psk: &[u8]) -> Result<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    configure_context(&mut builder)?;
    let mut identity = identity.as_bytes().to_vec();
    identity.push(0);
    let psk = psk.to_vec();
    builder.set_psk_client_callback(move |_, _, identity_output, psk_output| {
        if identity_output.len() < identity.len() {
            return Err(ErrorStack::get());
        }
        identity_output[..identity.len()].copy_from_slice(&identity);
        if psk_output.len() < psk.len() {
            return Err(ErrorStack::get());
        }
        psk_output[..psk.len()].copy_from_slice(&psk);
        Ok(psk.len())
    });
    Ok(builder.build())
}

fn configure_context(context: &mut SslContextBuilder) -> Result<()> {
    context.set_security_level(0);
    context.set_cipher_list(LEGACY_PSK_CIPHERS)?;
    context.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    context.set_max_proto_version(Some(SslVersion::TLS1_2))?;
    let dh = Dh::get_2048_256()?;
    context.set_tmp_dh(&dh)?;
    context.set_verify(SslVerifyMode::NONE);
    Ok(())
}

pub trait SyncStream: Read + Write {}
impl<T: Read + Write> SyncStream for T {}
