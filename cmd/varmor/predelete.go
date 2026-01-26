// Copyright 2026 vArmor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"time"

	varmorclient "github.com/bytedance/vArmor/pkg/client/clientset/versioned"
	"github.com/go-logr/logr"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func preDeleteHook(kubeClient *kubernetes.Clientset, varmorClient *varmorclient.Clientset, logger logr.Logger) error {
	// Delete all vArmor resources
	logger = logger.WithName("PRE-DELETE")
	logger.Info("Try to delete all vArmor resources")

	var err error
	// Delete all VarmorClusterPolicy objects
	e := deleteVarmorClusterPolicies(varmorClient, logger)
	if e != nil {
		err = e
	}

	// Delete all VarmorPolicy objects in all namespaces
	e = deleteVarmorPolicies(kubeClient, varmorClient, logger)
	if e != nil {
		err = e
	}

	// Wait for all armorprofile objects to be deleted
	time.Sleep(5 * time.Second)
	logger.Info("done")

	return err
}

func deleteVarmorClusterPolicies(varmorClient *varmorclient.Clientset, logger logr.Logger) error {
	// Use DeleteCollection to delete all VarmorClusterPolicy objects
	err := varmorClient.CrdV1beta1().VarmorClusterPolicies().DeleteCollection(
		context.Background(),
		v1.DeleteOptions{},
		v1.ListOptions{},
	)
	if err != nil {
		logger.Error(err, "Failed to delete VarmorClusterPolicy objects")
	} else {
		logger.Info("Successfully deleted all VarmorClusterPolicy objects")
	}

	return err
}

func deleteVarmorPolicies(kubeClient *kubernetes.Clientset, varmorClient *varmorclient.Clientset, logger logr.Logger) error {
	// Get all namespaces
	namespaces, err := kubeClient.CoreV1().Namespaces().List(context.Background(), v1.ListOptions{})
	if err != nil {
		logger.Error(err, "Failed to list namespaces")
		return err
	}

	// Delete VarmorPolicy objects in each namespace
	for _, namespace := range namespaces.Items {
		namespaceLogger := logger.WithValues("namespace", namespace.Name)

		e := varmorClient.CrdV1beta1().VarmorPolicies(namespace.Name).DeleteCollection(
			context.Background(),
			v1.DeleteOptions{},
			v1.ListOptions{},
		)
		if e != nil {
			namespaceLogger.Error(err, "Failed to delete VarmorPolicy objects")
			err = e
		} else {
			namespaceLogger.Info("Successfully deleted VarmorPolicy objects")
		}
	}
	return err
}
