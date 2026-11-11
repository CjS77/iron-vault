//! The TPM work: creating a TPM approval key and signing with it (`design/tpm-approval-signer.md` "The TPM approval
//! key", "Helper protocol").
//!
//! Every refusal that needs no authorization comes before the one authorized command, so it spends no try, and every
//! handle is flushed on every path: without a resource manager a leaked handle would stay in the TPM.

use std::str::FromStr;

use bitfield::BitRange;
use iron_vault_tpm_protocol::{Request, Response, SignRequest, TpmAuthValue, TpmKeyParts};
use iron_vault_tpm_signer::{LockoutReserve, is_signable, low_s_signature, sec1_point};
use sha2::{Digest as _, Sha256};
use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
use tss_esapi::constants::response_code::{Tss2ResponseCode, Tss2ResponseCodeKind};
use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK, TPMA_PERMANENT_INLOCKOUT};
use tss_esapi::constants::{CapabilityType, PropertyTag, SessionType};
use tss_esapi::handles::{KeyHandle, ObjectHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    Auth, CapabilityData, Digest, EccPoint, EccScheme, HashScheme, HashcheckTicket, Private, Public, PublicBuffer, PublicBuilder,
    PublicEccParametersBuilder, Signature, SignatureScheme, SymmetricDefinition, SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;
use tss_esapi::{Context, Error, WrapperErrorKind};

/// Why a step stopped short of its answer: a refusal to send as it is, or a TSS failure to map to a status.
enum Stop {
    Refuse(Box<Response>),
    Tss(Error),
}

impl From<Response> for Stop {
    fn from(response: Response) -> Self {
        Stop::Refuse(Box::new(response))
    }
}

impl From<Error> for Stop {
    fn from(error: Error) -> Self {
        Stop::Tss(error)
    }
}

type Step<T> = Result<T, Stop>;

/// Stops with `refusal`, if there is one.
fn refuse(refusal: Option<Response>) -> Step<()> {
    refusal.map_or(Ok(()), |response| Err(response.into()))
}

/// The helper's answer to `request` on the TPM `tcti` names.
pub fn answer(tcti: &str, request: Request) -> Response {
    let outcome = match request {
        Request::Create { auth } => create(tcti, &auth),
        Request::Sign(request) => sign(tcti, &request),
    };
    outcome.unwrap_or_else(|stop| match stop {
        Stop::Refuse(response) => *response,
        Stop::Tss(error) => tpm_error(error),
    })
}

/// Create (`01`): the settings check, then the key under a transient primary, in a salted session.
fn create(tcti: &str, auth: &TpmAuthValue) -> Step<Response> {
    let mut context = open(tcti)?;
    refuse(read_reserve(&mut context)?.settings_refusal())?;
    with_primary(&mut context, |context, primary| {
        let primary_name = context.tr_get_name(primary.into())?.value().to_vec();
        let template = approval_key_template(EccPoint::default())?;
        let auth = Auth::try_from(auth.as_bytes().to_vec())?;
        let created = with_salted_session(context, primary, |context| {
            Ok(context.create(primary, template, Some(auth), None, None, None)?)
        })?;
        let public_key = public_point(&created.out_public).ok_or(Response::KeyMismatch)?;
        let key = TpmKeyParts {
            primary_name,
            public: PublicBuffer::try_from(created.out_public)?.marshall()?,
            private: marshall_private(&created.out_private),
        };
        Ok(Response::Created { key, public_key })
    })
}

/// Sign (`02`): the message, the settings, the primary's name and the loaded key are each checked before the reserve
/// and the one authorized command.
fn sign(tcti: &str, request: &SignRequest) -> Step<Response> {
    if !is_signable(&request.message) {
        return Err(Response::RefusedMessage.into());
    }
    let public = PublicBuffer::unmarshall(&request.key.public)
        .and_then(Public::try_from)
        .map_err(|_| Response::Malformed)?;
    let private = unmarshall_private(&request.key.private).ok_or(Response::Malformed)?;
    let mut context = open(tcti)?;
    let reserve = read_reserve(&mut context)?;
    refuse(reserve.settings_refusal())?;
    with_primary(&mut context, |context, primary| {
        if context.tr_get_name(primary.into())?.value() != request.key.primary_name.as_slice() {
            return Err(Response::NotThisTpm.into());
        }
        let key = context.execute_with_session(Some(AuthSession::Password), |context| context.load(primary, private, public))?;
        with_flushed(context, key.into(), |context| {
            check_pinned(context, key, &request.pinned_key)?;
            refuse(reserve.try_refusal())?;
            context.tr_set_auth(key.into(), Auth::try_from(request.auth.as_bytes().to_vec())?)?;
            let digest = Digest::try_from(Sha256::digest(&request.message).to_vec())?;
            let scheme = SignatureScheme::EcDsa {
                hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
            };
            let signature = with_salted_session(context, primary, |context| {
                let ticket = null_ticket()?;
                context
                    .sign(key, digest, scheme, ticket)
                    .map_err(|error| sign_failure(error, &reserve))
            })?;
            Ok(Response::Signed {
                signature: signature_bytes(&signature).ok_or(Response::KeyMismatch)?,
            })
        })
    })
}

fn open(tcti: &str) -> Step<Context> {
    Ok(Context::new(TctiNameConf::from_str(tcti)?)?)
}

/// The dictionary-attack state, read fresh: `TPM2_PT_PERMANENT` through `TPM2_PT_LOCKOUT_INTERVAL` in one call.
fn read_reserve(context: &mut Context) -> Step<LockoutReserve> {
    let first = PropertyTag::Permanent;
    let count = u32::from(PropertyTag::LockoutInterval) - u32::from(first) + 1;
    let (data, _) =
        context.execute_without_session(|context| context.get_capability(CapabilityType::TpmProperties, first.into(), count))?;
    let missing = || Stop::Tss(Error::WrapperError(WrapperErrorKind::WrongValueFromTpm));
    let CapabilityData::TpmProperties(properties) = data else {
        return Err(missing());
    };
    let value = |tag| properties.find(tag).map(|property| property.value());
    Ok(LockoutReserve {
        counter: value(PropertyTag::LockoutCounter).ok_or_else(missing)?,
        max_tries: value(PropertyTag::MaxAuthFail).ok_or_else(missing)?,
        interval_seconds: value(PropertyTag::LockoutInterval).ok_or_else(missing)?,
        in_lockout: value(PropertyTag::Permanent).ok_or_else(missing)? & TPMA_PERMANENT_INLOCKOUT != 0,
    })
}

/// Runs `f` with the transient storage primary, from the TCG storage root key template for ECC NIST P-256, and
/// flushes it. The same TPM always derives the same key, so nothing persists in the TPM.
fn with_primary<T>(context: &mut Context, f: impl FnOnce(&mut Context, KeyHandle) -> Step<T>) -> Step<T> {
    let template = storage_primary_template()?;
    let primary = context
        .execute_with_session(Some(AuthSession::Password), |context| {
            context.create_primary(Hierarchy::Owner, template, None, None, None, None)
        })?
        .key_handle;
    with_flushed(context, primary.into(), |context| f(context, primary))
}

/// Runs `f` with an HMAC session salted with `primary`, with parameter encryption, then flushes the session. Salting
/// keeps a recorded TPM bus from testing PIN guesses offline against the session HMAC.
fn with_salted_session<T>(context: &mut Context, primary: KeyHandle, f: impl FnOnce(&mut Context) -> Step<T>) -> Step<T> {
    let session = context
        .start_auth_session(
            Some(primary),
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?
        .ok_or(Stop::Tss(Error::WrapperError(WrapperErrorKind::WrongValueFromTpm)))?;
    let flush = ObjectHandle::from(tss_esapi::handles::SessionHandle::from(session));
    with_flushed(context, flush, |context| {
        let (attributes, mask) = SessionAttributesBuilder::new()
            .with_continue_session(true)
            .with_decrypt(true)
            .build();
        context.tr_sess_set_attributes(session, attributes, mask)?;
        context.execute_with_session(Some(session), f)
    })
}

/// Runs `f`, then flushes `handle` whatever `f` returned. A flush failure after a success is reported, since it leaves
/// a handle in the TPM.
fn with_flushed<T>(context: &mut Context, handle: ObjectHandle, f: impl FnOnce(&mut Context) -> Step<T>) -> Step<T> {
    let result = f(context);
    let flushed = context.flush_context(handle);
    let value = result?;
    flushed?;
    Ok(value)
}

/// Refuses with `05` unless the loaded key, as the TPM reads it back, is the approval key template with the pinned
/// point: a blob replaced in the state directory, even by a key the same TPM made, cannot sign for a pinned approver.
fn check_pinned(context: &mut Context, key: KeyHandle, pinned: &[u8; 65]) -> Step<()> {
    let (public, _, _) = context.execute_without_session(|context| context.read_public(key))?;
    let Public::Ecc { unique, .. } = &public else {
        return Err(Response::KeyMismatch.into());
    };
    let expected = approval_key_template(unique.clone())?;
    match public == expected && public_point(&public).as_ref() == Some(pinned) {
        true => Ok(()),
        false => Err(Response::KeyMismatch.into()),
    }
}

/// The TCG storage root key template for ECC NIST P-256: a restricted decryption key, `noDA`, AES-128-CFB, with a
/// zero-length unique field.
fn storage_primary_template() -> Result<Public, Error> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()?;
    let parameters =
        PublicEccParametersBuilder::new_restricted_decryption_key(SymmetricDefinitionObject::AES_128_CFB, EccCurve::NistP256).build()?;
    ecc_public(attributes, parameters, EccPoint::default())
}

/// The TPM approval key: an unrestricted ECDSA P-256 signing key bound to this TPM, generated inside it, whose use needs
/// the authorization value. `noDA` is clear, so every wrong PIN counts against the TPM's lockout; `adminWithPolicy` is
/// clear and there is no policy.
fn approval_key_template(unique: EccPoint) -> Result<Public, Error> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .build()?;
    let scheme = EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256));
    let parameters = PublicEccParametersBuilder::new_unrestricted_signing_key(scheme, EccCurve::NistP256).build()?;
    ecc_public(attributes, parameters, unique)
}

fn ecc_public(
    attributes: tss_esapi::attributes::ObjectAttributes,
    parameters: tss_esapi::structures::PublicEccParameters,
    unique: EccPoint,
) -> Result<Public, Error> {
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(parameters)
        .with_ecc_unique_identifier(unique)
        .build()
}

/// The key's uncompressed SEC1 point.
fn public_point(public: &Public) -> Option<[u8; 65]> {
    match public {
        Public::Ecc { unique, .. } => sec1_point(unique.x().value(), unique.y().value()),
        _ => None,
    }
}

/// `r ‖ s` with low `s`, from an ECDSA signature.
fn signature_bytes(signature: &Signature) -> Option<[u8; 64]> {
    match signature {
        Signature::EcDsa(ecc) => low_s_signature(ecc.signature_r().value(), ecc.signature_s().value()),
        _ => None,
    }
}

/// A null hash-check ticket: the key is unrestricted, so the TPM needs no proof that it hashed the digest itself.
fn null_ticket() -> Result<HashcheckTicket, Error> {
    HashcheckTicket::try_from(TPMT_TK_HASHCHECK {
        tag: TPM2_ST_HASHCHECK,
        hierarchy: TPM2_RH_NULL,
        digest: Default::default(),
    })
}

/// A marshalled `TPM2B_PRIVATE`: its `u16` big-endian size, then the bytes. A `Private` holds at most a few hundred
/// bytes, so the size always fits.
fn marshall_private(private: &Private) -> Vec<u8> {
    let bytes = private.value();
    [&(bytes.len() as u16).to_be_bytes(), bytes].concat()
}

/// The `Private` a marshalled `TPM2B_PRIVATE` holds, accepted only when its size is exactly the bytes that follow.
fn unmarshall_private(bytes: &[u8]) -> Option<Private> {
    let (size, rest) = bytes.split_first_chunk::<2>()?;
    match usize::from(u16::from_be_bytes(*size)) == rest.len() {
        true => Private::try_from(rest.to_vec()).ok(),
        false => None,
    }
}

/// How the key's own `TPM2_Sign` failed. Only there is a refused authorization value the PIN's: a wrong PIN, one try
/// spent. Lockout there means the TPM went into lockout after the reserve was read, so the wait is at least the interval
/// at which the TPM forgets one failure, the earliest it can leave lockout.
fn sign_failure(error: Error, reserve: &LockoutReserve) -> Stop {
    let kind = match &error {
        Error::Tss2Error(code) => code.kind(),
        Error::WrapperError(_) => None,
    };
    match kind {
        Some(Tss2ResponseCodeKind::AuthFail | Tss2ResponseCodeKind::BadAuth) => Response::WrongPin.into(),
        Some(Tss2ResponseCodeKind::Lockout) => Response::LockedOut {
            wait_seconds: u64::from(reserve.interval_seconds),
        }
        .into(),
        _ => Stop::Tss(error),
    }
}

/// `08` with the TPM response code, or 0 when the failure has none (a TSS wrapper or TCTI error). An authorization
/// failure anywhere but the key's sign, such as an owner authorization another OS set, lands here: no PIN was tried.
fn tpm_error(error: Error) -> Response {
    let code = match error {
        Error::Tss2Error(code) => raw_code(code),
        Error::WrapperError(_) => 0,
    };
    Response::TpmError { code }
}

/// The whole `TSS2_RC`, which `tss-esapi` keeps in private fields; its bitfield types give it up through `BitRange`.
fn raw_code(code: Tss2ResponseCode) -> u32 {
    match code {
        Tss2ResponseCode::Success => 0,
        Tss2ResponseCode::FormatZero(code) => code.bit_range(31, 0),
        Tss2ResponseCode::FormatOne(code) => code.bit_range(31, 0),
    }
}
