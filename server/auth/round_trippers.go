package auth

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net/http"
	"regexp"
)

type impersonateRoundTripper struct {
	rt       http.RoundTripper
	username string
}

// NewImpersonateRoundTripper provides a RoundTripper which will preform a SubjectAccessReview for K8S API calls
func NewImpersonateRoundTripper(rt http.RoundTripper, username string) http.RoundTripper {
	return &impersonateRoundTripper{
		rt:       rt,
		username: username,
	}
}

func (rt *impersonateRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	impersonateClient := GetImpersonateClient(req.Context())
	if impersonateClient == nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("`impersonate.Client` is missing from HTTP context"))
	}

	urlPath := req.URL.Path
	urlQuery := req.URL.Query()
	log.WithFields(
		log.Fields{"Method": req.Method, "Path": urlPath, "Query": urlQuery},
	).Debug("ImpersonateRoundTripper")

	// extract ResourceAttributes from the request URL path
	re := regexp.MustCompile(
		`^(?:/api|/apis/(?P<GROUP>[^/]+))/(?P<VERSION>[^/]+)(?:/namespaces/(?P<NAMESPACE>[^/]+))?/(?P<RESOURCETYPE>[^/\n]+)(?:/(?P<NAME>[^/\n]+))?(?:/(?P<SUBRESOURCE>[^/\n]+))?$`,
	)
	matches := re.FindStringSubmatch(urlPath)
	if matches == nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("Invalid Kubernetes Resource URI path: %s", urlPath))
	}
	namespace := ""
	if re.SubexpIndex("NAMESPACE") != -1 {
		namespace = matches[re.SubexpIndex("NAMESPACE")]
	}
	resourceGroup := ""
	if re.SubexpIndex("GROUP") != -1 {
		resourceGroup = matches[re.SubexpIndex("GROUP")]
	}
	resourceVersion := ""
	if re.SubexpIndex("VERSION") != -1 {
		resourceVersion = matches[re.SubexpIndex("VERSION")]
	}
	resourceType := ""
	if re.SubexpIndex("RESOURCETYPE") != -1 {
		resourceType = matches[re.SubexpIndex("RESOURCETYPE")]
	}
	resourceName := ""
	if re.SubexpIndex("NAME") != -1 {
		resourceName = matches[re.SubexpIndex("NAME")]
	}
	subresource := ""
	if re.SubexpIndex("NAME") != -1 {
		subresource = matches[re.SubexpIndex("NAME")]
	}

	// calculate the resource verb
	verb := ""
	switch req.Method {
	case "", "GET":
		verb = "get"

		// TODO: define boolean variable (outside this switch) if acting on collection, then check with if statement here
		//       (https://kubernetes.io/docs/reference/access-authn-authz/authorization/#determine-the-request-verb)
		//verb = "list"

		// TODO: check if "watch=1" is in query
		//       (https://kubernetes.io/docs/reference/access-authn-authz/authorization/#determine-the-request-verb)
		//verb = "watch"
	case "POST":
		verb = "create"
	case "PUT":
		verb = "update"
	case "PATCH":
		verb = "patch"
	case "DELETE":
		verb = "delete"

		// TODO: define boolean variable (outside this switch) if acting on collection, then check with if statement here
		//       (https://kubernetes.io/docs/reference/access-authn-authz/authorization/#determine-the-request-verb)
		//verb = "deletecollection"
	default:
		return nil, status.Error(codes.Internal, fmt.Sprintf("Could not calcluate kubernetes resource verb for %s on %s", req.Method, req.URL))
	}

	err := impersonateClient.AccessReview(
		req.Context(),
		rt.username,
		namespace,
		verb,
		resourceGroup,
		resourceVersion,
		resourceType,
		resourceName,
		subresource,
	)
	if err != nil {
		// TODO: this is causing a 500 (internal status error) to the user, can we make it 404?
		return nil, err
	}

	return rt.rt.RoundTrip(req)
}
