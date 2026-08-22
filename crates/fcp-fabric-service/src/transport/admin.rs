// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! Authenticated tenant administration and role-step-up routes.

#[allow(clippy::wildcard_imports)]
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InviteAccountRequest {
    localpart: String,
    initial_role: Role,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChangeRoleRequest {
    role: Role,
    grant: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StepUpRequest {
    code: String,
    role: Role,
    grant: bool,
}

#[derive(Serialize)]
struct CreatedAccountResponse {
    account_id: String,
}

pub(super) async fn invite_account(
    State(state): State<Arc<FabricHttpState>>,
    headers: HeaderMap,
    Json(request): Json<InviteAccountRequest>,
) -> axum::response::Response {
    let Some(services) = &state.mfa_session else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let authenticated =
        match authenticate_admin(services, &headers, Permission::ManageAccounts).await {
            Ok(authenticated) => authenticated,
            Err(response) => return *response,
        };
    let Ok(localpart) = Localpart::parse(&request.localpart) else {
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    };
    let correlation_id = format!("http-admin-invite-{}", Uuid::now_v7());
    let command = InviteAccount {
        tenant_id: authenticated.context.tenant_id(),
        localpart,
        initial_role: request.initial_role,
        actor: administration_actor(&authenticated, false),
        correlation_id,
    };
    match services.store.invite_account(&command).await {
        Ok(account_id) => (
            StatusCode::CREATED,
            Json(CreatedAccountResponse {
                account_id: account_id.to_string(),
            }),
        )
            .into_response(),
        Err(StoreError::Administration(_)) => StatusCode::FORBIDDEN.into_response(),
        Err(error) => {
            tracing::error!(error = %error, "Fabric account invitation failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

pub(super) async fn begin_role_change_step_up(
    State(state): State<Arc<FabricHttpState>>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Json(request): Json<StepUpRequest>,
) -> axum::response::Response {
    let Some(services) = &state.mfa_session else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let authenticated = match authenticate_admin(services, &headers, Permission::ManageRoles).await
    {
        Ok(authenticated) => authenticated,
        Err(response) => return *response,
    };
    let Ok(target_account_id) = Uuid::parse_str(&account_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let correlation_id = format!("http-admin-role-step-up-{}", Uuid::now_v7());
    match services
        .step_up
        .issue_role_change(IssueRoleChangeStepUp {
            tenant_id: authenticated.context.tenant_id(),
            account_id: authenticated.context.account_id(),
            family_id: authenticated.family_id,
            target: RoleChangeTarget {
                account_id: AccountId::from_uuid(target_account_id),
                role: request.role,
                grant: request.grant,
            },
            code: &request.code,
            correlation_id: &correlation_id,
            now: time::OffsetDateTime::now_utc(),
        })
        .await
    {
        Ok(StepUpIssueOutcome::Granted(grant)) => {
            let cookie = step_up_cookie(grant.token.expose_secret());
            let Ok(cookie) = HeaderValue::from_str(&cookie) else {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            };
            let mut response = StatusCode::NO_CONTENT.into_response();
            response.headers_mut().append(header::SET_COOKIE, cookie);
            response
        }
        Ok(StepUpIssueOutcome::Denied) => generic_login_denial(),
        Err(error) => {
            tracing::error!(error = %error, "Fabric role-change step-up issuance failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

pub(super) async fn change_account_role(
    State(state): State<Arc<FabricHttpState>>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Json(request): Json<ChangeRoleRequest>,
) -> axum::response::Response {
    let Some(services) = &state.mfa_session else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let authenticated = match authenticate_admin(services, &headers, Permission::ManageRoles).await
    {
        Ok(authenticated) => authenticated,
        Err(response) => return *response,
    };
    let Ok(account_id) = Uuid::parse_str(&account_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let target_account_id = AccountId::from_uuid(account_id);
    let correlation_id = format!("http-admin-role-{}", Uuid::now_v7());
    let command = ChangeRole {
        tenant_id: authenticated.context.tenant_id(),
        target_account_id,
        role: request.role,
        grant: request.grant,
        actor: administration_actor(&authenticated, true),
        correlation_id: correlation_id.clone(),
    };
    if command.validate().is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(step_up_token) = browser_cookie(&headers, STEP_UP_COOKIE) else {
        return step_up_required();
    };
    let accepted = match services
        .step_up
        .consume_role_change(
            authenticated.context.tenant_id(),
            authenticated.context.account_id(),
            authenticated.family_id,
            RoleChangeTarget {
                account_id: target_account_id,
                role: command.role,
                grant: command.grant,
            },
            &step_up_token,
            &correlation_id,
        )
        .await
    {
        Ok(accepted) => accepted,
        Err(error) => {
            tracing::error!(error = %error, "Fabric role-change step-up consumption failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    if !accepted {
        return step_up_required();
    }
    let mut response = match services.store.change_role(&command).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(StoreError::Administration(_)) => StatusCode::FORBIDDEN.into_response(),
        Err(error) => {
            tracing::error!(error = %error, "Fabric account role change failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    };
    clear_step_up_cookie(response.headers_mut());
    response
}
