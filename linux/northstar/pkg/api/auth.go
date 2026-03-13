package api

import (
	"context"

	northstar "bonfire/northstar/proto"
	"connectrpc.com/connect"
)

func (s *NorthstarServer) Login(
	ctx context.Context,
	req *connect.Request[northstar.LoginRequest],
) (*connect.Response[northstar.LoginResponse], error) {

	return connect.NewResponse(&northstar.LoginResponse{
		Token: "dummy-token",
	}), nil
}
