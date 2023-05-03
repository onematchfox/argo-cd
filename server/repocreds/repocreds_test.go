package repocreds

import (
	"context"
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/argoproj/argo-cd/v2/common"
	"github.com/argoproj/argo-cd/v2/pkg/apiclient/repocreds"
	appsv1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	"github.com/argoproj/argo-cd/v2/reposerver/apiclient"
	"github.com/argoproj/argo-cd/v2/reposerver/apiclient/mocks"
	"github.com/argoproj/argo-cd/v2/util/assets"
	dbmocks "github.com/argoproj/argo-cd/v2/util/db/mocks"
	"github.com/argoproj/argo-cd/v2/util/rbac"
	"github.com/argoproj/argo-cd/v2/util/settings"
)

const testNamespace = "default"

var (
	argocdCM = corev1.ConfigMap{
		ObjectMeta: v1.ObjectMeta{
			Namespace: testNamespace,
			Name:      "argocd-cm",
			Labels: map[string]string{
				"app.kubernetes.io/part-of": "argocd",
			},
		},
	}
	argocdSecret = corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "argocd-secret",
			Namespace: testNamespace,
		},
		Data: map[string][]byte{
			"admin.password":   []byte("test"),
			"server.secretkey": []byte("test"),
		},
	}
)

func TestRepositoryCredentialsServer(t *testing.T) {
	kubeclientset := fake.NewSimpleClientset(&argocdCM, &argocdSecret)
	settingsMgr := settings.NewSettingsManager(context.Background(), kubeclientset, testNamespace)
	enforcer := newEnforcer(kubeclientset)

	t.Run("Test_Get", func(t *testing.T) {
		repoCredsServerClient := mocks.RepoServerServiceClient{}
		repoCredsServerClient.On("TestRepository", mock.Anything, mock.Anything).Return(&apiclient.TestRepositoryResponse{}, nil)
		repoServerClientset := mocks.Clientset{RepoServerServiceClient: &repoCredsServerClient}

		url := "https://test"
		db := &dbmocks.ArgoDB{}
		db.On("GetRepositoryCredentials", context.TODO(), url).Return(&appsv1.RepoCreds{URL: url}, nil)

		s := NewServer(&repoServerClientset, db, enforcer, settingsMgr)
		repo, err := s.GetRepositoryCredentials(context.Background(), &repocreds.RepoCredsQuery{
			Url: url,
		})
		assert.Nil(t, err)
		assert.Equal(t, repo.URL, url)
	})

	t.Run("Test_GetWithErrorShouldReturn403", func(t *testing.T) {
		repoCredsServerClient := mocks.RepoServerServiceClient{}
		repoServerClientset := mocks.Clientset{RepoServerServiceClient: &repoCredsServerClient}

		url := "https://test"
		db := &dbmocks.ArgoDB{}
		db.On("GetRepositoryCredentials", context.TODO(), url).Return(nil, errors.New("some error"))

		s := NewServer(&repoServerClientset, db, enforcer, settingsMgr)
		repo, err := s.GetRepositoryCredentials(context.TODO(), &repocreds.RepoCredsQuery{
			Url: url,
		})
		assert.Nil(t, repo)
		assert.Equal(t, err, errPermissionDenied)
	})

	t.Run("Test_GetWithNotExistRepoShouldReturn404", func(t *testing.T) {
		repoCredsServerClient := mocks.RepoServerServiceClient{}
		repoServerClientset := mocks.Clientset{RepoServerServiceClient: &repoCredsServerClient}

		url := "https://test"
		db := &dbmocks.ArgoDB{}
		db.On("GetRepositoryCredentials", context.TODO(), url).Return(nil, nil)

		s := NewServer(&repoServerClientset, db, enforcer, settingsMgr)
		repo, err := s.GetRepositoryCredentials(context.TODO(), &repocreds.RepoCredsQuery{
			Url: url,
		})
		assert.Nil(t, repo)
		assert.Equal(t, "rpc error: code = NotFound desc = repository credentials 'https://test' not found", err.Error())
	})
}

func newEnforcer(kubeclientset *fake.Clientset) *rbac.Enforcer {
	enforcer := rbac.NewEnforcer(kubeclientset, testNamespace, common.ArgoCDRBACConfigMapName, nil)
	_ = enforcer.SetBuiltinPolicy(assets.BuiltinPolicyCSV)
	enforcer.SetDefaultRole("role:admin")
	enforcer.SetClaimsEnforcerFunc(func(claims jwt.Claims, rvals ...interface{}) bool {
		return true
	})
	return enforcer
}
