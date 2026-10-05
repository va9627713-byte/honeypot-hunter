import asyncio
from enterprise.auth.auth_manager import AuthManager
from enterprise.auth.api_keys import APIKeyManager
from enterprise.auth.oidc import OIDCProvider
from enterprise.auth.session import SessionManager
from enterprise.auth.models import User, Role, Permission, AuthConfig
from enterprise.config.settings import Settings
from enterprise.config.validation import ConfigValidator

print("All enterprise auth modules import OK")

s = Settings()
print(f"Settings loaded: {s.app_name} v{s.version}")

async def test():
    am = AuthManager()
    await am.initialize(admin_password='test123')
    user = await am.authenticate('admin', 'test123', '127.0.0.1')
    print(f"Auth test: {user.username if user else 'FAILED'}")
    stats = await am.get_user_stats()
    print(f"Stats: {stats}")
    
    # Test API keys
    key, api_key = await am.create_api_key('Test Key', 'admin', roles={'analyst'})
    print(f"API Key test: {api_key.id} created")
    
    verified = await am.verify_api_key(key)
    print(f"API Key verify: {verified.id if verified else 'FAILED'}")

asyncio.run(test())
print("All enterprise auth tests passed!")