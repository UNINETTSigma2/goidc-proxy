package conf

import (
	"gopkg.in/yaml.v2"
	"flag"
	"path/filepath"
	"io/ioutil"
	"time"
	"os"
	"strconv"
)

var (
	configfile = flag.String("c", "example.yml", "Use the specified `configfile`")
)
var Config = Configer{
	Proxy:ProxyConfig{
		Target:"http://127.0.0.1:8000",
		InsecureSkipVerify:false},
	Engine:EngineConfig{
		ClientID:"00000-0000-000-000-00",
		ClientSecret: "00000-0000-000-000-00",
		IssuerUrl:"https://auth.dataporten.no",
		RedirectUrl: "http://localhost:8888/oauth2/callback",
		Scopes:"userid,groups",
		Signkey:"testtesttesttest",
		GroupEndpoint:"",
		TokenType:"oauth2",
		JwtTokenIssuer:"https://jwt.example.no",
		TwoFactor:TwoFactorConfig{All:false, RedictOnResponse:false},
		Role:"",
		Logging:LogConfig{Level:"debug"}},
	Server:ServerConfig{
		Port:8888,
		HealthPort:1337,
		ReadTimeout:time.Second * 10,
		WriteTimeout:time.Second * 20,
		IdleTimeout:time.Minute * 2,
		SSL:false,
		SecureCookie:false},
}

type ProxyConfig struct {
	Target             string `yaml:"target"`
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
}
type EngineConfig struct {
	ClientID             string `yaml:"client_id"`
	ClientSecret         string `yaml:"client_secret"`
	IssuerUrl            string `yaml:"issuer_url"`
	RedirectUrl          string `yaml:"redirect_url"`
	Scopes               string `yaml:"scopes"`
	Role                 string `yaml:"role"`
	Signkey              string `yaml:"signkey"`
	GroupEndpoint        string `yaml:"groups_endpoint"`
	TokenType            string `yaml:"token_type"`
	JwtTokenIssuer       string `yaml:"jwt_token_issuer"`
	XhrEndpoints         string `yaml:"xhr_endpoints"`
	AuthorizedPrincipals string `yaml:"authorized_principals"`
	TwoFactor            TwoFactorConfig `yaml:"twofactor"`
	Logging              LogConfig `yaml:"logging"`
}
type TwoFactorConfig struct {
	All              bool  `yaml:"all"`
	Principals       string  `yaml:"principals"`
	AcrValues        string  `yaml:"acr_values"`
	Backend          string  `yaml:"backend"`
	RedictOnResponse bool  `yaml:"rediect_on_response"`
}
type LogConfig struct {
	Level string `yaml:"level"`
}
type Configer struct {
	Yaml   []byte
	Proxy  ProxyConfig `yaml:"proxy"`
	Engine EngineConfig `yaml:"engine"`
	Server ServerConfig `yaml:"server"`
}
type ServerConfig struct {
	Port         uint16 `yaml:"port"`
	HealthPort   uint16 `yaml:"health_port"`
	Cert         string `yaml:"cert"`
	Key          string `yaml:"key"`
	ReadTimeout  time.Duration `yaml:"readtimeout"`
	WriteTimeout time.Duration `yaml:"writetimeout"`
	IdleTimeout  time.Duration `yaml:"idletimeout"`
	SSL          bool `yaml:"ssl"`
	SecureCookie bool `yaml:"secure_cookie"`
}

func LoadConfig() {
	// load env config
	if val, ok := os.LookupEnv("GOIDC_Proxy_TARGET"); ok {
		Config.Proxy.Target = val
	}
	if val, ok := os.LookupEnv("GOIDC_Proxy_InsecureSkipVerify"); ok {
		Config.Proxy.InsecureSkipVerify = val == "true"
	}
	if val, ok := os.LookupEnv("GOIDC_Engine_ClientID"); ok {
		Config.Engine.ClientID = val
	}
	if val, ok := os.LookupEnv("GOIDC_Engine_ClientSecret"); ok {
		Config.Engine.ClientSecret = val
	}
	if val, ok := os.LookupEnv("GOIDC_Engine_IssuerURL"); ok {
		Config.Engine.IssuerUrl = val
	}
	if val, ok := os.LookupEnv("GOIDC_Engine_RedirectUrl"); ok {
		Config.Engine.RedirectUrl = val
	}
	if val, ok := os.LookupEnv("GOIDC_Engine_Scopes"); ok {
		Config.Engine.Scopes = val
	}
	if val, ok := os.LookupEnv("GOIDC_Engine_Role"); ok {
		Config.Engine.Role = val
	}
	if val, ok := os.LookupEnv("GOIDC_Engine_Signkey"); ok {
		Config.Engine.Signkey = val
	}
	if val, ok := os.LookupEnv("GOIDC_Engine_GroupEndpoint"); ok {
		Config.Engine.GroupEndpoint = val
	}
	if val, ok := os.LookupEnv("GOIDC_Engine_TokenType"); ok {
		Config.Engine.TokenType = val
	}
	if val, ok := os.LookupEnv("GOIDC_Engine_JwtTokenIssuer"); ok {
		Config.Engine.JwtTokenIssuer = val
	}
	if val, ok := os.LookupEnv("GOIDC_Engine_XhrEndpoints"); ok {
		Config.Engine.XhrEndpoints = val
	}
	if val, ok := os.LookupEnv("GOIDC_Engine_AuthorizedPrincipals"); ok {
		Config.Engine.AuthorizedPrincipals = val
	}

	if val, ok := os.LookupEnv("GOIDC_Engine_TwoFactor_All"); ok {
		Config.Engine.TwoFactor.All = val == "true"
	}
	if val, ok := os.LookupEnv("GOIDC_Engine_TwoFactor_Principals"); ok {
		Config.Engine.TwoFactor.Principals = val
	}
	if val, ok := os.LookupEnv("GOIDC_Engine_TwoFactor_AcrValues"); ok {
		Config.Engine.TwoFactor.AcrValues = val
	}
	if val, ok := os.LookupEnv("GOIDC_Engine_TwoFactor_Backend"); ok {
		Config.Engine.TwoFactor.Backend = val
	}
	if val, ok := os.LookupEnv("GOIDC_Engine_TwoFactor_RedictOnResponse"); ok {
		Config.Engine.TwoFactor.RedictOnResponse = val == "true"
	}

	if val, ok := os.LookupEnv("GOIDC_Engine_Logging_Level"); ok {
		Config.Engine.Logging.Level = val
	}

	if val, ok := os.LookupEnv("GOIDC_Server_PORT"); ok {
		Port, _ := strconv.ParseUint(val, 10, 16)
		Config.Server.Port = uint16(Port)
	}
	if val, ok := os.LookupEnv("GOIDC_Server_HealthPort"); ok {
		Port, _ := strconv.ParseUint(val, 10, 16)
		Config.Server.HealthPort = uint16(Port)
	}
	if val, ok := os.LookupEnv("GOIDC_Server_Cert"); ok {
		Config.Server.Cert = val
	}
	if val, ok := os.LookupEnv("GOIDC_Server_Key"); ok {
		Config.Server.Key = val
	}
	if val, ok := os.LookupEnv("GOIDC_Server_SSL"); ok {
		Config.Server.SSL = val == "true"
	}
	if val, ok := os.LookupEnv("GOIDC_Server_SecureCookie"); ok {
		Config.Server.SecureCookie = val == "true"
	}

	// load file config
	filename, err := filepath.Abs(*configfile)
	if err != nil {
		return
	}
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}
	Config.Yaml = yamlFile

	err = yaml.Unmarshal(yamlFile, &Config)
	if err != nil {
		panic(err)
	}
}
