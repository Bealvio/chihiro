package cmd

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Debug cluster resources",
	Long:  `Show raw cluster resources to help debug parsing issues`,
	Run: func(cmd *cobra.Command, args []string) {
		runDebug()
	},
}

func init() {
	rootCmd.AddCommand(debugCmd)
}

func runDebug() {
	kubeconfig := viper.GetString("kubeconfig")
	if kubeconfig == "" {
		kubeconfig = os.Getenv("KUBECONFIG")
	}

	var config *rest.Config
	var err error

	if kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		config, err = rest.InClusterConfig()
	}

	if err != nil {
		slog.Error("Failed to create kubernetes config", "error", err)
		os.Exit(1)
	}

	client, err := dynamic.NewForConfig(config)
	if err != nil {
		slog.Error("Failed to create kubernetes client", "error", err)
		os.Exit(1)
	}

	gvr := schema.GroupVersionResource{
		Group:    "cluster.x-k8s.io",
		Version:  "v1beta1",
		Resource: "clusters",
	}

	list, err := client.Resource(gvr).List(context.TODO(), metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/managed-by=chihiro",
	})
	if err != nil {
		slog.Error("Error loading clusters for debug", "error", err)
		os.Exit(1)
	}

	slog.Info("Found clusters for debug", "count", len(list.Items))

	for i, item := range list.Items {
		slog.Info("Cluster debug info", "index", i+1, "name", item.GetName(), "namespace", item.GetNamespace())

		// Pretty print the raw object
		jsonData, err := json.MarshalIndent(item.Object, "", "  ")
		if err != nil {
			slog.Error("Error marshaling cluster for debug output", "cluster_name", item.GetName(), "namespace", item.GetNamespace(), "error", err)
			continue
		}

		slog.Debug("Cluster raw data", "cluster_name", item.GetName(), "namespace", item.GetNamespace(), "data", string(jsonData))
	}
}