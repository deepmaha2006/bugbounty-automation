"""Organization routes: info about the caller's own tenant.

Full organization management (renaming, inviting teammates, cross-org admin)
is Phase 3 (RBAC) scope — this is deliberately just enough for a user to see
which organization they're in and how big it is.
"""
from fastapi import APIRouter, Depends, HTTPException

from webapp import db
from webapp.routers.auth import require_user
from webapp.schemas import OrganizationOut

router = APIRouter(prefix="/api/organizations", tags=["organizations"])


@router.get("/me", response_model=OrganizationOut)
def my_organization(user: dict = Depends(require_user)):
    org = db.get_organization(user["organization_id"])
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    counts = db.organization_counts(org["id"])
    return OrganizationOut(
        id=org["id"], name=org["name"], slug=org["slug"],
        created_at=org["created_at"],
        user_count=counts["users"], asset_count=counts["assets"],
    )
