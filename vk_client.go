package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	vkAPIBase = "https://api.vk.com/method"
	vkVer     = "5.199"
)

// NodeInfo — узел из реестра VK Bot
type NodeInfo struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Pubkey string `json:"pubkey"`
	Kind   string `json:"kind"`
}

// VKClient — клиент реестра узлов OwOCloak через VK Bot
type VKClient struct {
	token     string
	groupID   int64
	sharedKey string
	botPeer   int64 // отрицательный ID группы
	myIP      string
	myPort    int
	myPubkey  string
	kind      string // "core" | "server" | "client"
	http      *http.Client
}

func NewVKClient(token string, groupID int64, sharedKey, ip string, port int, pubkey, kind string) *VKClient {
	return &VKClient{
		token:     token,
		groupID:   groupID,
		sharedKey: sharedKey,
		botPeer:   -groupID,
		myIP:      ip,
		myPort:    port,
		myPubkey:  pubkey,
		kind:      kind,
		http:      &http.Client{Timeout: 15 * time.Second},
	}
}

// sign — HMAC-SHA256(ip:port:pubkey, sharedKey) — совпадает с bot.py
func (c *VKClient) sign() string {
	data := fmt.Sprintf("%s:%d:%s", c.myIP, c.myPort, c.myPubkey)
	mac := hmac.New(sha256.New, []byte(c.sharedKey))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

// vkCall — базовый POST к VK API
func (c *VKClient) vkCall(method string, params map[string]string) (map[string]interface{}, error) {
	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	form.Set("access_token", c.token)
	form.Set("v", vkVer)

	resp, err := c.http.Post(
		fmt.Sprintf("%s/%s", vkAPIBase, method),
		"application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("vk http: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("vk parse: %w", err)
	}
	if errObj, ok := result["error"]; ok {
		return nil, fmt.Errorf("vk api error: %v", errObj)
	}
	if r, ok := result["response"]; ok {
		if rm, ok := r.(map[string]interface{}); ok {
			return rm, nil
		}
		return map[string]interface{}{"value": r}, nil
	}
	return result, nil
}

// sendCmd — отправить JSON-команду боту
func (c *VKClient) sendCmd(cmd map[string]interface{}) error {
	msg, err := json.Marshal(cmd)
	if err != nil {
		return err
	}
	_, err = c.vkCall("messages.send", map[string]string{
		"peer_id":   fmt.Sprintf("%d", c.botPeer),
		"message":   string(msg),
		"random_id": fmt.Sprintf("%d", time.Now().UnixMilli()),
	})
	return err
}

// Register — зарегистрировать себя как relay-узел
func (c *VKClient) Register() error {
	err := c.sendCmd(map[string]interface{}{
		"action": "register",
		"ip":     c.myIP,
		"port":   c.myPort,
		"pubkey": c.myPubkey,
		"kind":   c.kind,
		"sig":    c.sign(),
	})
	if err != nil {
		return fmt.Errorf("vk register: %w", err)
	}
	log.Printf("[VKClient] registered as %s at %s:%d", c.kind, c.myIP, c.myPort)
	return nil
}

// Ping — сообщить что узел жив
func (c *VKClient) Ping() error {
	return c.sendCmd(map[string]interface{}{
		"action": "ping",
		"ip":     c.myIP,
		"port":   c.myPort,
		"pubkey": c.myPubkey,
		"sig":    c.sign(),
	})
}

// Unregister — снять узел с регистрации при выключении
func (c *VKClient) Unregister() error {
	err := c.sendCmd(map[string]interface{}{
		"action": "unregister",
		"ip":     c.myIP,
		"port":   c.myPort,
		"pubkey": c.myPubkey,
		"sig":    c.sign(),
	})
	if err != nil {
		return fmt.Errorf("vk unregister: %w", err)
	}
	log.Printf("[VKClient] unregistered %s:%d", c.myIP, c.myPort)
	return nil
}

// StartPingLoop — фоновый пинг каждые 60 секунд
func (c *VKClient) StartPingLoop(ctx context.Context) {
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := c.Ping(); err != nil {
					log.Printf("[VKClient] ping error: %v", err)
				} else {
					log.Printf("[VKClient] pinged registry %s:%d", c.myIP, c.myPort)
				}
			}
		}
	}()
}

// GetNodes — получить список живых узлов из реестра
func (c *VKClient) GetNodes(kind string) ([]NodeInfo, error) {
	cmd := map[string]interface{}{
		"action": "list",
		"key":    c.sharedKey,
	}
	if kind != "" {
		cmd["kind"] = kind
	}
	if err := c.sendCmd(cmd); err != nil {
		return nil, err
	}
	// TODO: читать ответ через Long Poll (сейчас бот отвечает асинхронно)
	// Для клиентской части используем отдельный Long Poll loop
	return nil, nil
}
