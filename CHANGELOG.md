# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-12-26

### Added

- Initial release
- Bitwise permission system with `PermissionActionRegistry` and `PermissionsManager`
- Permission metadata support (`category`, `description`, `action_descriptions`)
- SQLAlchemy async repository (`AsyncPermissionRepository`)
- FastAPI integration with `PermissionDependency` and `create_permission_dependency`
- Permission discovery endpoint via `get_permissions_router`
- TTL-based permission caching
- Support for both `get_current_user_id` and `get_current_user` authentication patterns
- `UserWithId` protocol for user objects with `.id` attribute
- Comprehensive test suite
- Example applications (basic usage and FastAPI app)
