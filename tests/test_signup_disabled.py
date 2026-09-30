def test_public_admin_signup_route_is_not_registered():
    from routes.admin import router

    paths = {route.path for route in router.routes}
    assert "/api/admin/auth/signup" not in paths
    assert "/api/admin/auth/signin" not in paths
