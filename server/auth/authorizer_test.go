package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// TODO: update/create tests for new `AccessReview(` function
func TestAuthorizer_CanI(t *testing.T) {
	kubeClient := &kubefake.Clientset{}
	allowed := true
	kubeClient.AddReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, &authorizationv1.SelfSubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{Allowed: allowed},
		}, nil
	})
	ctx := context.WithValue(context.Background(), KubeKey, kubeClient)
	t.Run("CanI", func(t *testing.T) {
		err := AccessReview(ctx, "", "", "", "", "", true)
		assert.NoError(t, err)
	})
	kubeClient.AddReactor("create", "selfsubjectrulesreviews", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, &authorizationv1.SelfSubjectRulesReview{
			Status: authorizationv1.SubjectRulesReviewStatus{
				ResourceRules: []authorizationv1.ResourceRule{{
					Verbs:         []string{"*"},
					ResourceNames: []string{"my-name"},
				}},
			},
		}, nil
	})
}
