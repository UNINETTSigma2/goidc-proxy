package conf

import (
	"errors"
	"github.com/spf13/viper"
)

func ReadConfig(filename string) error {

	viper.SetConfigName(filename)
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		return errors.New(err.Error() + ("Fatal error in config file."))
	}
	return nil
}

func GetStringValue(key string) string {
	return viper.GetString(key)
}

func GetBoolValue(key string) bool {
	return viper.GetBool(key)
}

func GetIntValue(key string) int {
	return viper.GetInt(key)
}

func GetStringArrayValue(key string) []string {
	return viper.GetStringSlice(key)
}

func GetStringMapString(key string) map[string]string {
	return viper.GetStringMapString(key)
}
