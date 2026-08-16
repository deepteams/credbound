package credbound

import (
	"fmt"
	"regexp"
	"slices"
)

var roleNamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
var workspacePermissionPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)

type compiledRole struct {
	definition  RoleDefinition
	roles       map[Role]struct{}
	permissions map[WorkspacePermission]struct{}
}

type roleCatalog struct {
	roles       map[Role]compiledRole
	permissions map[WorkspacePermission]struct{}
}

func buildRoleCatalog(configured []RoleDefinition) (*roleCatalog, error) {
	definitions := map[Role]RoleDefinition{
		RoleMember: {Role: RoleMember, Permissions: []WorkspacePermission{PermissionWorkspaceAccess}},
		RoleAdmin: {
			Role: RoleAdmin,
			Permissions: []WorkspacePermission{
				PermissionWorkspaceAccess, PermissionWorkspaceUsersRead, PermissionWorkspaceUsersWrite,
				PermissionWorkspaceSettingsWrite,
				PermissionWorkspaceRBACWrite, PermissionWorkspaceAuditRead,
				PermissionOAuthResourceManage,
			},
			Inherits: []Role{RoleMember},
		},
	}
	for _, raw := range configured {
		if !roleNamePattern.MatchString(string(raw.Role)) {
			return nil, fmt.Errorf("%w: invalid workspace role %q", ErrInvalidInput, raw.Role)
		}
		definition := definitions[raw.Role]
		definition.Role = raw.Role
		definition.Permissions = append(definition.Permissions, raw.Permissions...)
		definition.Inherits = append(definition.Inherits, raw.Inherits...)
		if raw.Role != RoleMember && raw.Role != RoleAdmin && !slices.Contains(definition.Inherits, RoleMember) {
			definition.Inherits = append(definition.Inherits, RoleMember)
		}
		definitions[raw.Role] = definition
	}

	allPermissions := make(map[WorkspacePermission]struct{})
	for role, definition := range definitions {
		definition.Permissions = uniqueWorkspacePermissions(definition.Permissions)
		definition.Inherits = uniqueRoles(definition.Inherits)
		for _, permission := range definition.Permissions {
			if !workspacePermissionPattern.MatchString(string(permission)) {
				return nil, fmt.Errorf("%w: invalid workspace permission %q", ErrInvalidInput, permission)
			}
			allPermissions[permission] = struct{}{}
		}
		definitions[role] = definition
	}
	admin := definitions[RoleAdmin]
	for permission := range allPermissions {
		admin.Permissions = append(admin.Permissions, permission)
	}
	admin.Permissions = uniqueWorkspacePermissions(admin.Permissions)
	definitions[RoleAdmin] = admin

	catalog := &roleCatalog{roles: make(map[Role]compiledRole, len(definitions)), permissions: allPermissions}
	visiting := make(map[Role]bool)
	visited := make(map[Role]bool)
	var compile func(Role) (compiledRole, error)
	compile = func(role Role) (compiledRole, error) {
		if compiled, ok := catalog.roles[role]; ok {
			return compiled, nil
		}
		definition, ok := definitions[role]
		if !ok {
			return compiledRole{}, fmt.Errorf("%w: unknown inherited workspace role %q", ErrInvalidInput, role)
		}
		if visiting[role] {
			return compiledRole{}, fmt.Errorf("%w: cyclic workspace role inheritance", ErrInvalidInput)
		}
		if visited[role] {
			return catalog.roles[role], nil
		}
		visiting[role] = true
		result := compiledRole{
			definition:  definition,
			roles:       map[Role]struct{}{role: {}},
			permissions: make(map[WorkspacePermission]struct{}),
		}
		for _, permission := range definition.Permissions {
			result.permissions[permission] = struct{}{}
		}
		for _, inheritedRole := range definition.Inherits {
			inherited, err := compile(inheritedRole)
			if err != nil {
				return compiledRole{}, err
			}
			for value := range inherited.roles {
				result.roles[value] = struct{}{}
			}
			for permission := range inherited.permissions {
				result.permissions[permission] = struct{}{}
			}
		}
		visiting[role], visited[role] = false, true
		catalog.roles[role] = result
		return result, nil
	}
	for role := range definitions {
		if _, err := compile(role); err != nil {
			return nil, err
		}
	}
	return catalog, nil
}

func uniqueWorkspacePermissions(values []WorkspacePermission) []WorkspacePermission {
	result := slices.Clone(values)
	slices.Sort(result)
	return slices.Compact(result)
}

func uniqueRoles(values []Role) []Role {
	result := slices.Clone(values)
	slices.Sort(result)
	return slices.Compact(result)
}

func (c *roleCatalog) normalize(role Role) (Role, error) {
	if c == nil {
		return "", fmt.Errorf("%w: workspace role catalog unavailable", ErrInvalidInput)
	}
	if _, ok := c.roles[role]; !ok {
		return "", fmt.Errorf("%w: unknown workspace role", ErrInvalidInput)
	}
	return role, nil
}

func (c *roleCatalog) includes(role, required Role) bool {
	compiled, ok := c.roles[role]
	if !ok {
		return false
	}
	_, ok = compiled.roles[required]
	return ok
}

func (c *roleCatalog) allows(role Role, permission WorkspacePermission) bool {
	compiled, ok := c.roles[role]
	if !ok {
		return false
	}
	_, ok = compiled.permissions[permission]
	return ok
}
