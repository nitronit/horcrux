// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.13.0
// source: cosigner_grpc_server.proto

package proto

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// ICosignerGRPCClient is the client API for ICosignerGRPC service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ICosignerGRPCClient interface {
	SetNoncesAndSign(ctx context.Context, in *CosignerGRPCSetNoncesAndSignRequest, opts ...grpc.CallOption) (*CosignerGRPCSetNoncesAndSignResponse, error)
	GetNonces(ctx context.Context, in *CosignerGRPCGetNoncesRequest, opts ...grpc.CallOption) (*CosignerGRPCGetNoncesResponse, error)
}

type iCosignerGRPCClient struct {
	cc grpc.ClientConnInterface
}

func NewICosignerGRPCClient(cc grpc.ClientConnInterface) ICosignerGRPCClient {
	return &iCosignerGRPCClient{cc}
}

func (c *iCosignerGRPCClient) SetNoncesAndSign(ctx context.Context, in *CosignerGRPCSetNoncesAndSignRequest, opts ...grpc.CallOption) (*CosignerGRPCSetNoncesAndSignResponse, error) {
	out := new(CosignerGRPCSetNoncesAndSignResponse)
	err := c.cc.Invoke(ctx, "/proto.ICosignerGRPC/SetNoncesAndSign", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *iCosignerGRPCClient) GetNonces(ctx context.Context, in *CosignerGRPCGetNoncesRequest, opts ...grpc.CallOption) (*CosignerGRPCGetNoncesResponse, error) {
	out := new(CosignerGRPCGetNoncesResponse)
	err := c.cc.Invoke(ctx, "/proto.ICosignerGRPC/GetNonces", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ICosignerGRPCServer is the server API for ICosignerGRPC service.
// All implementations must embed UnimplementedICosignerGRPCServer
// for forward compatibility
type ICosignerGRPCServer interface {
	SetNoncesAndSign(context.Context, *CosignerGRPCSetNoncesAndSignRequest) (*CosignerGRPCSetNoncesAndSignResponse, error)
	GetNonces(context.Context, *CosignerGRPCGetNoncesRequest) (*CosignerGRPCGetNoncesResponse, error)
	mustEmbedUnimplementedICosignerGRPCServer()
}

// UnimplementedICosignerGRPCServer must be embedded to have forward compatible implementations.
type UnimplementedICosignerGRPCServer struct {
}

func (UnimplementedICosignerGRPCServer) SetNoncesAndSign(context.Context, *CosignerGRPCSetNoncesAndSignRequest) (*CosignerGRPCSetNoncesAndSignResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetNoncesAndSign not implemented")
}
func (UnimplementedICosignerGRPCServer) GetNonces(context.Context, *CosignerGRPCGetNoncesRequest) (*CosignerGRPCGetNoncesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetNonces not implemented")
}
func (UnimplementedICosignerGRPCServer) mustEmbedUnimplementedICosignerGRPCServer() {}

// UnsafeICosignerGRPCServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ICosignerGRPCServer will
// result in compilation errors.
type UnsafeICosignerGRPCServer interface {
	mustEmbedUnimplementedICosignerGRPCServer()
}

func RegisterICosignerGRPCServer(s grpc.ServiceRegistrar, srv ICosignerGRPCServer) {
	s.RegisterService(&ICosignerGRPC_ServiceDesc, srv)
}

func _ICosignerGRPC_SetNoncesAndSign_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CosignerGRPCSetNoncesAndSignRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ICosignerGRPCServer).SetNoncesAndSign(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.ICosignerGRPC/SetNoncesAndSign",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ICosignerGRPCServer).SetNoncesAndSign(ctx, req.(*CosignerGRPCSetNoncesAndSignRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ICosignerGRPC_GetNonces_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CosignerGRPCGetNoncesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ICosignerGRPCServer).GetNonces(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.ICosignerGRPC/GetNonces",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ICosignerGRPCServer).GetNonces(ctx, req.(*CosignerGRPCGetNoncesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ICosignerGRPC_ServiceDesc is the grpc.ServiceDesc for ICosignerGRPC service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ICosignerGRPC_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "proto.ICosignerGRPC",
	HandlerType: (*ICosignerGRPCServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SetNoncesAndSign",
			Handler:    _ICosignerGRPC_SetNoncesAndSign_Handler,
		},
		{
			MethodName: "GetNonces",
			Handler:    _ICosignerGRPC_GetNonces_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "cosigner_grpc_server.proto",
}

// IRaftGRPCClient is the client API for IRaftGRPC service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type IRaftGRPCClient interface {
	SignBlock(ctx context.Context, in *RaftGRPCSignBlockRequest, opts ...grpc.CallOption) (*RaftGRPCSignBlockResponse, error)
	TransferLeadership(ctx context.Context, in *RaftGRPCTransferLeadershipRequest, opts ...grpc.CallOption) (*RaftGRPCTransferLeadershipResponse, error)
	GetLeader(ctx context.Context, in *RaftGRPCGetLeaderRequest, opts ...grpc.CallOption) (*RaftGRPCGetLeaderResponse, error)
}

type iRaftGRPCClient struct {
	cc grpc.ClientConnInterface
}

func NewIRaftGRPCClient(cc grpc.ClientConnInterface) IRaftGRPCClient {
	return &iRaftGRPCClient{cc}
}

func (c *iRaftGRPCClient) SignBlock(ctx context.Context, in *RaftGRPCSignBlockRequest, opts ...grpc.CallOption) (*RaftGRPCSignBlockResponse, error) {
	out := new(RaftGRPCSignBlockResponse)
	err := c.cc.Invoke(ctx, "/proto.IRaftGRPC/SignBlock", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *iRaftGRPCClient) TransferLeadership(ctx context.Context, in *RaftGRPCTransferLeadershipRequest, opts ...grpc.CallOption) (*RaftGRPCTransferLeadershipResponse, error) {
	out := new(RaftGRPCTransferLeadershipResponse)
	err := c.cc.Invoke(ctx, "/proto.IRaftGRPC/TransferLeadership", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *iRaftGRPCClient) GetLeader(ctx context.Context, in *RaftGRPCGetLeaderRequest, opts ...grpc.CallOption) (*RaftGRPCGetLeaderResponse, error) {
	out := new(RaftGRPCGetLeaderResponse)
	err := c.cc.Invoke(ctx, "/proto.IRaftGRPC/GetLeader", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// IRaftGRPCServer is the server API for IRaftGRPC service.
// All implementations must embed UnimplementedIRaftGRPCServer
// for forward compatibility
type IRaftGRPCServer interface {
	SignBlock(context.Context, *RaftGRPCSignBlockRequest) (*RaftGRPCSignBlockResponse, error)
	TransferLeadership(context.Context, *RaftGRPCTransferLeadershipRequest) (*RaftGRPCTransferLeadershipResponse, error)
	GetLeader(context.Context, *RaftGRPCGetLeaderRequest) (*RaftGRPCGetLeaderResponse, error)
	mustEmbedUnimplementedIRaftGRPCServer()
}

// UnimplementedIRaftGRPCServer must be embedded to have forward compatible implementations.
type UnimplementedIRaftGRPCServer struct {
}

func (UnimplementedIRaftGRPCServer) SignBlock(context.Context, *RaftGRPCSignBlockRequest) (*RaftGRPCSignBlockResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SignBlock not implemented")
}
func (UnimplementedIRaftGRPCServer) TransferLeadership(context.Context, *RaftGRPCTransferLeadershipRequest) (*RaftGRPCTransferLeadershipResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method TransferLeadership not implemented")
}
func (UnimplementedIRaftGRPCServer) GetLeader(context.Context, *RaftGRPCGetLeaderRequest) (*RaftGRPCGetLeaderResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetLeader not implemented")
}
func (UnimplementedIRaftGRPCServer) mustEmbedUnimplementedIRaftGRPCServer() {}

// UnsafeIRaftGRPCServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to IRaftGRPCServer will
// result in compilation errors.
type UnsafeIRaftGRPCServer interface {
	mustEmbedUnimplementedIRaftGRPCServer()
}

func RegisterIRaftGRPCServer(s grpc.ServiceRegistrar, srv IRaftGRPCServer) {
	s.RegisterService(&IRaftGRPC_ServiceDesc, srv)
}

func _IRaftGRPC_SignBlock_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RaftGRPCSignBlockRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IRaftGRPCServer).SignBlock(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.IRaftGRPC/SignBlock",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IRaftGRPCServer).SignBlock(ctx, req.(*RaftGRPCSignBlockRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IRaftGRPC_TransferLeadership_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RaftGRPCTransferLeadershipRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IRaftGRPCServer).TransferLeadership(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.IRaftGRPC/TransferLeadership",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IRaftGRPCServer).TransferLeadership(ctx, req.(*RaftGRPCTransferLeadershipRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IRaftGRPC_GetLeader_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RaftGRPCGetLeaderRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IRaftGRPCServer).GetLeader(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.IRaftGRPC/GetLeader",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IRaftGRPCServer).GetLeader(ctx, req.(*RaftGRPCGetLeaderRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// IRaftGRPC_ServiceDesc is the grpc.ServiceDesc for IRaftGRPC service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var IRaftGRPC_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "proto.IRaftGRPC",
	HandlerType: (*IRaftGRPCServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SignBlock",
			Handler:    _IRaftGRPC_SignBlock_Handler,
		},
		{
			MethodName: "TransferLeadership",
			Handler:    _IRaftGRPC_TransferLeadership_Handler,
		},
		{
			MethodName: "GetLeader",
			Handler:    _IRaftGRPC_GetLeader_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "cosigner_grpc_server.proto",
}
