package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

type wechatLoginResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

type wechatStateValue struct {
	Scene     string `json:"scene"`
	UserId    int    `json:"user_id,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

var wechatStateStore = struct {
	sync.Mutex
	values map[string]wechatStateValue
}{values: make(map[string]wechatStateValue)}

func buildWeChatAuthURL(state string) string {
	if common.WeChatServerAddress == "" {
		return ""
	}
	base := strings.TrimRight(common.WeChatServerAddress, "/")
	return fmt.Sprintf("%s/api/wechat?state=%s", base, url.QueryEscape(state))
}

func saveWeChatState(state string, value wechatStateValue) error {
	wechatStateStore.Lock()
	defer wechatStateStore.Unlock()
	wechatStateStore.values[state] = value
	return nil
}

func consumeWeChatState(state string) (*wechatStateValue, error) {
	if state == "" {
		return nil, errors.New("无效的 state")
	}
	wechatStateStore.Lock()
	defer wechatStateStore.Unlock()
	value, ok := wechatStateStore.values[state]
	if !ok {
		return nil, errors.New("state 已过期或不存在")
	}
	delete(wechatStateStore.values, state)
	if time.Now().Unix()-value.CreatedAt > int64(common.VerificationValidMinutes*60) {
		return nil, errors.New("state 已过期")
	}
	return &value, nil
}

func getWeChatIdByCode(code string) (string, error) {
	if code == "" {
		return "", errors.New("无效的参数")
	}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/wechat/user?code=%s", common.WeChatServerAddress, url.QueryEscape(code)), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", common.WeChatServerToken)
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	httpResponse, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer httpResponse.Body.Close()
	var res wechatLoginResponse
	err = json.NewDecoder(httpResponse.Body).Decode(&res)
	if err != nil {
		return "", err
	}
	if !res.Success {
		return "", errors.New(res.Message)
	}
	if res.Data == "" {
		return "", errors.New("验证码错误或已过期")
	}
	return res.Data, nil
}

func WeChatAuth(c *gin.Context) {
	if !common.WeChatAuthEnabled {
		c.JSON(http.StatusOK, gin.H{
			"message": "管理员未开启通过微信登录以及注册",
			"success": false,
		})
		return
	}
	code := c.Query("code")
	wechatId, err := getWeChatIdByCode(code)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	user := model.User{
		WeChatId: wechatId,
	}
	if model.IsWeChatIdAlreadyTaken(wechatId) {
		err := user.FillUserByWeChatId()
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": err.Error(),
			})
			return
		}
		if user.Id == 0 {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "用户已注销",
			})
			return
		}
	} else {
		if common.RegisterEnabled {
			user.Username = "wechat_" + strconv.Itoa(model.GetMaxUserId()+1)
			user.DisplayName = "WeChat User"
			user.Role = common.RoleCommonUser
			user.Status = common.UserStatusEnabled

			if err := user.Insert(0); err != nil {
				c.JSON(http.StatusOK, gin.H{
					"success": false,
					"message": err.Error(),
				})
				return
			}
		} else {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "管理员关闭了新用户注册",
			})
			return
		}
	}

	if user.Status != common.UserStatusEnabled {
		c.JSON(http.StatusOK, gin.H{
			"message": "用户已被封禁",
			"success": false,
		})
		return
	}
	setupLogin(&user, c)
}

type wechatBindRequest struct {
	Code string `json:"code"`
}

func WeChatBind(c *gin.Context) {
	if !common.WeChatAuthEnabled {
		c.JSON(http.StatusOK, gin.H{
			"message": "管理员未开启通过微信登录以及注册",
			"success": false,
		})
		return
	}
	var req wechatBindRequest
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无效的请求",
		})
		return
	}
	code := req.Code
	wechatId, err := getWeChatIdByCode(code)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"message": err.Error(),
			"success": false,
		})
		return
	}
	if model.IsWeChatIdAlreadyTaken(wechatId) {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "该微信账号已被绑定",
		})
		return
	}
	session := sessions.Default(c)
	id := session.Get("id")
	user := model.User{
		Id: id.(int),
	}
	err = user.FillUserById()
	if err != nil {
		common.ApiError(c, err)
		return
	}
	user.WeChatId = wechatId
	err = user.Update(false)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
	})
	return
}

func WeChatBindURL(c *gin.Context) {
	if !common.WeChatAuthEnabled {
		common.ApiErrorMsg(c, "管理员未开启通过微信登录以及注册")
		return
	}
	state := common.GenerateVerificationCode(32)
	if err := saveWeChatState(state, wechatStateValue{Scene: "bind", UserId: c.GetInt("id"), CreatedAt: time.Now().Unix()}); err != nil {
		common.ApiError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data": gin.H{
			"state": state,
			"url":   buildWeChatAuthURL(state),
		},
	})
}

func WeChatLoginURL(c *gin.Context) {
	if !common.WeChatAuthEnabled {
		common.ApiErrorMsg(c, "管理员未开启通过微信登录以及注册")
		return
	}
	state := common.GenerateVerificationCode(32)
	if err := saveWeChatState(state, wechatStateValue{Scene: "login", CreatedAt: time.Now().Unix()}); err != nil {
		common.ApiError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data": gin.H{
			"state": state,
			"url":   buildWeChatAuthURL(state),
		},
	})
}

func WeChatCallback(c *gin.Context) {
	if !common.WeChatAuthEnabled {
		common.ApiErrorMsg(c, "管理员未开启通过微信登录以及注册")
		return
	}
	stateValue, err := consumeWeChatState(c.Query("state"))
	if err != nil {
		common.ApiErrorMsg(c, err.Error())
		return
	}
	wechatId, err := getWeChatIdByCode(c.Query("code"))
	if err != nil {
		common.ApiError(c, err)
		return
	}
	switch stateValue.Scene {
	case "bind":
		bindWeChatToUser(c, stateValue.UserId, wechatId)
	case "login":
		loginOrCreateByWeChat(c, wechatId)
	default:
		common.ApiErrorMsg(c, "无效的微信登录场景")
	}
}

func bindWeChatToUser(c *gin.Context, userId int, wechatId string) {
	if userId == 0 {
		common.ApiErrorMsg(c, "无效的用户")
		return
	}
	if model.IsWeChatIdAlreadyTaken(wechatId) {
		common.ApiErrorMsg(c, "该微信账号已被绑定")
		return
	}
	user, err := model.GetUserById(userId, true)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	if user.WeChatId != "" {
		common.ApiErrorMsg(c, "当前用户已绑定微信")
		return
	}
	user.WeChatId = wechatId
	if err := user.Update(false); err != nil {
		common.ApiError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": ""})
}

func loginOrCreateByWeChat(c *gin.Context, wechatId string) {
	user := model.User{WeChatId: wechatId}
	if model.IsWeChatIdAlreadyTaken(wechatId) {
		if err := user.FillUserByWeChatId(); err != nil {
			common.ApiError(c, err)
			return
		}
		if user.Status != common.UserStatusEnabled {
			common.ApiErrorMsg(c, "用户已被封禁")
			return
		}
		setupLogin(&user, c)
		return
	}
	if !common.RegisterEnabled {
		common.ApiErrorMsg(c, "管理员关闭了新用户注册")
		return
	}
	user.Username = model.GenerateUniqueUsername("wx")
	user.DisplayName = "微信用户"
	user.Password = common.GenerateVerificationCode(32)
	user.Role = common.RoleCommonUser
	user.Status = common.UserStatusEnabled
	if err := user.Insert(0); err != nil {
		common.ApiError(c, err)
		return
	}
	created := model.User{WeChatId: wechatId}
	if err := created.FillUserByWeChatId(); err != nil {
		common.ApiError(c, err)
		return
	}
	if err := createDefaultTokenForUser(created.Id, created.Username); err != nil {
		common.ApiError(c, err)
		return
	}
	setupLogin(&created, c)
}
