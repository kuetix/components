package transitions

import (
	"net/http"

	tokenutil "github.com/kuetix/components/pkg/services"
	"github.com/kuetix/engine/pkg/domain"
	"github.com/kuetix/engine/pkg/domain/interfaces"
	"github.com/kuetix/engine/pkg/domain/issues"
	"github.com/kuetix/engine/pkg/helpers"
	"github.com/kuetix/engine/pkg/workflow"
)

type jwtTransitions struct {
	workflow.BaseServiceTransition
}

//goland:noinspection GoUnusedExportedFunction
func NewJwtTransitions() interfaces.ServiceTransitions {
	return &jwtTransitions{}
}

func (jt *jwtTransitions) GenerateToken(jwtIssuer, encryptedId string) (r domain.FlowStepResult) {
	env := jt.Ctx.Engine.GetApplication().Env
	c, ok := env.Config.Items["jwt"].(domain.IniConfig)
	if !ok {
		panic("jwt config not found")
	}
	if _, ok := c["ACCESS_TOKEN_SECRET"]; !ok {
		jt.SetError(issues.NewIssue("ACCESS_TOKEN_SECRET is not set in jwt config", nil), http.StatusInternalServerError)
		r.Success = false
		return
	}
	expiry, _ := helpers.MustInt(c["ACCESS_TOKEN_EXPIRY_HOUR"])
	accessToken, err := tokenutil.CreateAccessToken(jwtIssuer, encryptedId, c["ACCESS_TOKEN_SECRET"].(string), expiry)
	if err != nil {
		jt.SetError(issues.NewIssue(err.Error(), err), http.StatusInternalServerError)
		r.Success = false
		return
	}

	expiry, _ = helpers.MustInt(c["REFRESH_TOKEN_EXPIRY_HOUR"])
	refreshToken, err := tokenutil.CreateRefreshToken(jwtIssuer, encryptedId, c["REFRESH_TOKEN_SECRET"].(string), expiry)
	if err != nil {
		jt.SetError(issues.NewIssue(err.Error(), err), http.StatusInternalServerError)
		r.Success = false
		return
	}

	loginToken := map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}

	jt.SetValue("loginToken", &loginToken)

	r.Response = &loginToken
	r.Success = true
	return
}
