/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by lister-gen. DO NOT EDIT.

package v1beta1

import (
	v1beta1 "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// ArmorProfileLister helps list ArmorProfiles.
// All objects returned here must be treated as read-only.
type ArmorProfileLister interface {
	// List lists all ArmorProfiles in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1beta1.ArmorProfile, err error)
	// ArmorProfiles returns an object that can list and get ArmorProfiles.
	ArmorProfiles(namespace string) ArmorProfileNamespaceLister
	ArmorProfileListerExpansion
}

// armorProfileLister implements the ArmorProfileLister interface.
type armorProfileLister struct {
	indexer cache.Indexer
}

// NewArmorProfileLister returns a new ArmorProfileLister.
func NewArmorProfileLister(indexer cache.Indexer) ArmorProfileLister {
	return &armorProfileLister{indexer: indexer}
}

// List lists all ArmorProfiles in the indexer.
func (s *armorProfileLister) List(selector labels.Selector) (ret []*v1beta1.ArmorProfile, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1beta1.ArmorProfile))
	})
	return ret, err
}

// ArmorProfiles returns an object that can list and get ArmorProfiles.
func (s *armorProfileLister) ArmorProfiles(namespace string) ArmorProfileNamespaceLister {
	return armorProfileNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// ArmorProfileNamespaceLister helps list and get ArmorProfiles.
// All objects returned here must be treated as read-only.
type ArmorProfileNamespaceLister interface {
	// List lists all ArmorProfiles in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1beta1.ArmorProfile, err error)
	// Get retrieves the ArmorProfile from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1beta1.ArmorProfile, error)
	ArmorProfileNamespaceListerExpansion
}

// armorProfileNamespaceLister implements the ArmorProfileNamespaceLister
// interface.
type armorProfileNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all ArmorProfiles in the indexer for a given namespace.
func (s armorProfileNamespaceLister) List(selector labels.Selector) (ret []*v1beta1.ArmorProfile, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1beta1.ArmorProfile))
	})
	return ret, err
}

// Get retrieves the ArmorProfile from the indexer for a given namespace and name.
func (s armorProfileNamespaceLister) Get(name string) (*v1beta1.ArmorProfile, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1beta1.Resource("armorprofile"), name)
	}
	return obj.(*v1beta1.ArmorProfile), nil
}