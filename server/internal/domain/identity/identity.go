// Package identity 定义账号、角色与会话的值对象。
package identity

import "time"

// Role 角色，按最小权限递增
type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

var roleRank = map[Role]int{
	RoleViewer:   1,
	RoleOperator: 2,
	RoleAdmin:    3,
}

// Rank 角色权重，未知角色为 0
func (r Role) Rank() int { return roleRank[r] }

// AtLeast 是否达到最小角色要求
func (r Role) AtLeast(min Role) bool { return r.Rank() >= min.Rank() }

// Valid 是否为已知角色
func (r Role) Valid() bool { return r.Rank() > 0 }

// User 对外暴露的用户信息
type User struct {
	Username string `json:"username"`
	Name     string `json:"name"`
	Role     Role   `json:"role"`
}

// Account 含敏感字段的账号记录，仅用于仓储层内部
type Account struct {
	ID        int64
	Username  string
	Name      string
	PwdHash   string
	Role      Role
	Disabled  bool
	LastLogin time.Time
}

// Session 服务端会话
type Session struct {
	Token     string
	User      User
	ExpiresAt time.Time
}
