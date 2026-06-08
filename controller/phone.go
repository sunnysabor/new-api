package controller

import (
	"errors"
	"net/http"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const phoneVerificationPurpose = "phone:"

type phoneCodeRequest struct {
	Phone   string `json:"phone"`
	Purpose string `json:"purpose"`
}

type phoneBindRequest struct {
	Phone string `json:"phone"`
	Code  string `json:"code"`
}

type phoneLoginRequest struct {
	Phone       string `json:"phone"`
	Code        string `json:"code"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

func normalizePhone(phone string) string {
	return strings.TrimSpace(phone)
}

func validPhonePurpose(purpose string) bool {
	switch purpose {
	case "bind", "login", "change":
		return true
	default:
		return false
	}
}

func verifyPhoneCode(phone string, code string, purpose string) bool {
	return common.VerifyCodeWithKey(phone, code, phoneVerificationPurpose+purpose)
}

func deletePhoneCode(phone string, purpose string) {
	common.DeleteKey(phone, phoneVerificationPurpose+purpose)
}

func SendPhoneVerification(c *gin.Context) {
	var req phoneCodeRequest
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		common.ApiErrorMsg(c, "无效的请求")
		return
	}
	req.Phone = normalizePhone(req.Phone)
	req.Purpose = strings.TrimSpace(req.Purpose)
	if req.Phone == "" || !validPhonePurpose(req.Purpose) {
		common.ApiErrorMsg(c, "无效的参数")
		return
	}
	if req.Purpose == "bind" && model.IsPhoneAlreadyTaken(req.Phone) {
		common.ApiErrorMsg(c, "手机号已被占用")
		return
	}
	code := common.GenerateVerificationCode(6)
	common.RegisterVerificationCodeWithKey(req.Phone, code, phoneVerificationPurpose+req.Purpose)
	data := gin.H{}
	if common.DebugEnabled {
		data["code"] = code
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "短信服务供应商未配置，验证码已生成，待接入供应商发送",
		"data":    data,
	})
}

func BindPhone(c *gin.Context) {
	var req phoneBindRequest
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		common.ApiErrorMsg(c, "无效的请求")
		return
	}
	req.Phone = normalizePhone(req.Phone)
	if req.Phone == "" || req.Code == "" {
		common.ApiErrorMsg(c, "无效的参数")
		return
	}
	if !verifyPhoneCode(req.Phone, req.Code, "bind") {
		common.ApiErrorMsg(c, "验证码错误或已过期")
		return
	}
	if model.IsPhoneAlreadyTaken(req.Phone) {
		common.ApiErrorMsg(c, "手机号已被占用")
		return
	}
	user, err := model.GetUserById(c.GetInt("id"), true)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	user.Phone = req.Phone
	if err := user.Update(false); err != nil {
		common.ApiError(c, err)
		return
	}
	deletePhoneCode(req.Phone, "bind")
	c.JSON(http.StatusOK, gin.H{"success": true, "message": ""})
}

func PhoneLogin(c *gin.Context) {
	var req phoneLoginRequest
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		common.ApiErrorMsg(c, "无效的请求")
		return
	}
	req.Phone = normalizePhone(req.Phone)
	req.Username = strings.TrimSpace(req.Username)
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	if req.Phone == "" || req.Code == "" {
		common.ApiErrorMsg(c, "无效的参数")
		return
	}
	if !verifyPhoneCode(req.Phone, req.Code, "login") {
		common.ApiErrorMsg(c, "验证码错误或已过期")
		return
	}
	user, err := model.GetUserByPhone(req.Phone)
	if err == nil {
		if user.Status != common.UserStatusEnabled {
			common.ApiErrorMsg(c, "用户已被封禁")
			return
		}
		deletePhoneCode(req.Phone, "login")
		setupLogin(user, c)
		return
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		common.ApiError(c, err)
		return
	}
	if !common.RegisterEnabled {
		common.ApiErrorMsg(c, "管理员关闭了新用户注册")
		return
	}
	if req.Username == "" {
		suffix := req.Phone
		if len(suffix) > 4 {
			suffix = suffix[len(suffix)-4:]
		}
		req.Username = model.GenerateUniqueUsername("phone_" + suffix)
	}
	if req.DisplayName == "" {
		req.DisplayName = req.Username
	}
	if exists, err := model.CheckUserExistOrDeleted(req.Username, ""); err != nil {
		common.ApiError(c, err)
		return
	} else if exists {
		common.ApiErrorMsg(c, "用户名已存在")
		return
	}
	password := common.GenerateVerificationCode(32)
	newUser := model.User{
		Username:    req.Username,
		Password:    password,
		DisplayName: req.DisplayName,
		Phone:       req.Phone,
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
	}
	if err := newUser.Insert(0); err != nil {
		common.ApiError(c, err)
		return
	}
	created, err := model.GetUserByPhone(req.Phone)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	if err := createDefaultTokenForUser(created.Id, created.Username); err != nil {
		common.ApiError(c, err)
		return
	}
	deletePhoneCode(req.Phone, "login")
	setupLogin(created, c)
}
