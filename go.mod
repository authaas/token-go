module github.com/authaas/token-jwt-go

go 1.27.1

require (
	buf.build/gen/go/authaas/identity/protocolbuffers/go v1.36.12-20260922233804-b037abb32578.2
	buf.build/gen/go/authaas/realm/protocolbuffers/go v1.36.12-20260923162914-d26a9bca8bb6.2
	buf.build/gen/go/authaas/token/protocolbuffers/go v1.36.12-20260926152351-01b1ffd69453.2
	github.com/golang-jwt/jwt/v5 v5.3.1
	google.golang.org/protobuf v1.36.12
)
