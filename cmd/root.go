package cmd

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "chihiro",
	Short: "A web application to watch and display Cluster API resources",
	Long: `Cluster Watcher is a web application that monitors Kubernetes Cluster API
custom resources and displays their information in a beautiful Material Design web interface.

The application provides real-time updates via WebSockets and shows cluster status,
health, and other important metrics in an easy-to-understand dashboard.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.chihiro.yaml)")
	rootCmd.PersistentFlags().String("kubeconfig", "", "path to kubeconfig file")
	rootCmd.PersistentFlags().Int("port", 8080, "port to run the web server on")
	rootCmd.PersistentFlags().String("host", "0.0.0.0", "host to bind the web server to")

	// OIDC configuration
	rootCmd.PersistentFlags().String("oidc-issuer-url", "", "OIDC issuer URL")
	rootCmd.PersistentFlags().String("oidc-client-id", "", "OIDC client ID")
	rootCmd.PersistentFlags().String("oidc-client-secret", "", "OIDC client secret")
	rootCmd.PersistentFlags().String("oidc-redirect-url", "", "OIDC redirect URL (default: http://host:port/auth/callback)")
	rootCmd.PersistentFlags().String("session-key", "", "Session encryption key (random if not provided)")

	viper.BindPFlag("kubeconfig", rootCmd.PersistentFlags().Lookup("kubeconfig"))
	viper.BindPFlag("port", rootCmd.PersistentFlags().Lookup("port"))
	viper.BindPFlag("host", rootCmd.PersistentFlags().Lookup("host"))
	viper.BindPFlag("oidc.issuer_url", rootCmd.PersistentFlags().Lookup("oidc-issuer-url"))
	viper.BindPFlag("oidc.client_id", rootCmd.PersistentFlags().Lookup("oidc-client-id"))
	viper.BindPFlag("oidc.client_secret", rootCmd.PersistentFlags().Lookup("oidc-client-secret"))
	viper.BindPFlag("oidc.redirect_url", rootCmd.PersistentFlags().Lookup("oidc-redirect-url"))
	viper.BindPFlag("oidc.session_key", rootCmd.PersistentFlags().Lookup("session-key"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".chihiro")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		slog.Debug("Using config file", "file", viper.ConfigFileUsed())
	}
}
