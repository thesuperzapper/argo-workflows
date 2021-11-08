package impersonate

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	auth "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"strings"
)

type Client interface {
	AccessReview(ctx context.Context, username string, namespace string, verb string, resourceGroup string, resourceVersion string, resourceType string, resourceName string, subresource string) error
}

type client struct {
	kubeClient kubernetes.Interface
}

func NewClient(kubeClient kubernetes.Interface) (Client, error) {
	return &client{kubeClient}, nil
}

func (s *client) AccessReview(ctx context.Context, username string, namespace string, verb string, resourceGroup string, resourceVersion string, resourceType string, resourceName string, subresource string) error {
	log.WithFields(log.Fields{
		"Namespace":   namespace,
		"Verb":        verb,
		"Group":       resourceGroup,
		"Version":     resourceVersion,
		"Resource":    resourceType,
		"Name":        resourceName,
		"Subresource": subresource,
	}).Debug(fmt.Printf("SubjectAccessReview - %s", username))

	review, err := s.kubeClient.AuthorizationV1().SubjectAccessReviews().Create(ctx, &auth.SubjectAccessReview{
		Spec: auth.SubjectAccessReviewSpec{
			User: username,
			// TODO: are we going to include groups?
			//Groups: rt.groups,
			ResourceAttributes: &auth.ResourceAttributes{
				Namespace:   namespace,
				Verb:        verb,
				Group:       resourceGroup,
				Version:     resourceVersion,
				Resource:    resourceType,
				Name:        resourceName,
				Subresource: subresource,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	if !review.Status.Allowed {
		// construct a human-friendly string to represent the resource
		resourceString := ""
		if resourceGroup != "" {
			resourceString += resourceGroup
		}
		if resourceVersion != "" {
			resourceString += "/" + resourceVersion
		}
		if resourceType != "" {
			resourceString += "/" + resourceType
		}
		if resourceName != "" {
			resourceString += "/" + resourceName
		}
		if subresource != "" {
			resourceString += "/" + subresource
		}
		resourceString = strings.TrimPrefix(resourceString, "/")

		return status.Error(
			codes.PermissionDenied,
			fmt.Sprintf("user '%s' is not allowed to '%s' %s in namespace '%s'",
				username,
				verb,
				resourceString,
				namespace,
			),
		)
	}

	return nil
}
