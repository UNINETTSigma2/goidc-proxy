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
	if val, ok := os.LookupEnv("GOIDC_TARGET"); ok {
		Config.Proxy.Target = val
	}
	if val, ok := os.LookupEnv("GOIDC_INSECURE_SKIP_VERIFY"); ok {
		Config.Proxy.InsecureSkipVerify = val == "true"
	}
	if val, ok := os.LookupEnv("GOIDC_ClientID"); ok {
		Config.Engine.ClientID = val
	}
	if val, ok := os.LookupEnv("GOIDC_ClientSecret"); ok {
		Config.Engine.ClientSecret = val
	}
	if val, ok := os.LookupEnv("GOIDC_INSECURE_SKIP_VERIFY"); ok {
		Config.Proxy.InsecureSkipVerify = val == "true"
	}
	if val, ok := os.LookupEnv("GOIDC_PORT"); ok {
		Port, _ := strconv.ParseUint(val, 10, 16)
		Config.Server.Port = uint16(Port)
	}

	if val, ok := os.LookupEnv("GOIDC_SSL"); ok {
		Config.Server.SSL = val == "true"
	}

	// load file config
	filename, err := filepath.Abs(*configfile)
	if err != nil {
		panic(err)
	}
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	Config.Yaml = yamlFile

	err = yaml.Unmarshal(yamlFile, &Config)
	if err != nil {
		panic(err)
	}
}
