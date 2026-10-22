from .permissions import is_analyst


def role(request):
    user = getattr(request, "user", None)
    analyst = is_analyst(user)
    return {"is_analyst": analyst, "user_role": "analyst" if analyst else "viewer"}
