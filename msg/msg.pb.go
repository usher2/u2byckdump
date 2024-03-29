// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.6.1
// source: msg/msg.proto

package msg

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type IDRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Query uint64 `protobuf:"varint,1,opt,name=query,proto3" json:"query,omitempty"`
}

func (x *IDRequest) Reset() {
	*x = IDRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_msg_msg_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IDRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IDRequest) ProtoMessage() {}

func (x *IDRequest) ProtoReflect() protoreflect.Message {
	mi := &file_msg_msg_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IDRequest.ProtoReflect.Descriptor instead.
func (*IDRequest) Descriptor() ([]byte, []int) {
	return file_msg_msg_proto_rawDescGZIP(), []int{0}
}

func (x *IDRequest) GetQuery() uint64 {
	if x != nil {
		return x.Query
	}
	return 0
}

type IP4Request struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Query uint32 `protobuf:"varint,1,opt,name=query,proto3" json:"query,omitempty"`
}

func (x *IP4Request) Reset() {
	*x = IP4Request{}
	if protoimpl.UnsafeEnabled {
		mi := &file_msg_msg_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IP4Request) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IP4Request) ProtoMessage() {}

func (x *IP4Request) ProtoReflect() protoreflect.Message {
	mi := &file_msg_msg_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IP4Request.ProtoReflect.Descriptor instead.
func (*IP4Request) Descriptor() ([]byte, []int) {
	return file_msg_msg_proto_rawDescGZIP(), []int{1}
}

func (x *IP4Request) GetQuery() uint32 {
	if x != nil {
		return x.Query
	}
	return 0
}

type URLRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Query string `protobuf:"bytes,1,opt,name=query,proto3" json:"query,omitempty"`
}

func (x *URLRequest) Reset() {
	*x = URLRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_msg_msg_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *URLRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*URLRequest) ProtoMessage() {}

func (x *URLRequest) ProtoReflect() protoreflect.Message {
	mi := &file_msg_msg_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use URLRequest.ProtoReflect.Descriptor instead.
func (*URLRequest) Descriptor() ([]byte, []int) {
	return file_msg_msg_proto_rawDescGZIP(), []int{2}
}

func (x *URLRequest) GetQuery() string {
	if x != nil {
		return x.Query
	}
	return ""
}

type DomainRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Query string `protobuf:"bytes,1,opt,name=query,proto3" json:"query,omitempty"`
}

func (x *DomainRequest) Reset() {
	*x = DomainRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_msg_msg_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DomainRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DomainRequest) ProtoMessage() {}

func (x *DomainRequest) ProtoReflect() protoreflect.Message {
	mi := &file_msg_msg_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DomainRequest.ProtoReflect.Descriptor instead.
func (*DomainRequest) Descriptor() ([]byte, []int) {
	return file_msg_msg_proto_rawDescGZIP(), []int{3}
}

func (x *DomainRequest) GetQuery() string {
	if x != nil {
		return x.Query
	}
	return ""
}

type SearchResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Error              string     `protobuf:"bytes,1,opt,name=error,proto3" json:"error,omitempty"`
	RegistryUpdateTime int64      `protobuf:"varint,2,opt,name=registryUpdateTime,proto3" json:"registryUpdateTime,omitempty"`
	Results            []*Content `protobuf:"bytes,3,rep,name=results,proto3" json:"results,omitempty"`
}

func (x *SearchResponse) Reset() {
	*x = SearchResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_msg_msg_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SearchResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SearchResponse) ProtoMessage() {}

func (x *SearchResponse) ProtoReflect() protoreflect.Message {
	mi := &file_msg_msg_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SearchResponse.ProtoReflect.Descriptor instead.
func (*SearchResponse) Descriptor() ([]byte, []int) {
	return file_msg_msg_proto_rawDescGZIP(), []int{4}
}

func (x *SearchResponse) GetError() string {
	if x != nil {
		return x.Error
	}
	return ""
}

func (x *SearchResponse) GetRegistryUpdateTime() int64 {
	if x != nil {
		return x.RegistryUpdateTime
	}
	return 0
}

func (x *SearchResponse) GetResults() []*Content {
	if x != nil {
		return x.Results
	}
	return nil
}

type StatRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Query string `protobuf:"bytes,1,opt,name=query,proto3" json:"query,omitempty"`
}

func (x *StatRequest) Reset() {
	*x = StatRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_msg_msg_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StatRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StatRequest) ProtoMessage() {}

func (x *StatRequest) ProtoReflect() protoreflect.Message {
	mi := &file_msg_msg_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StatRequest.ProtoReflect.Descriptor instead.
func (*StatRequest) Descriptor() ([]byte, []int) {
	return file_msg_msg_proto_rawDescGZIP(), []int{5}
}

func (x *StatRequest) GetQuery() string {
	if x != nil {
		return x.Query
	}
	return ""
}

type StatResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Error string `protobuf:"bytes,1,opt,name=error,proto3" json:"error,omitempty"`
	Stats []byte `protobuf:"bytes,2,opt,name=stats,proto3" json:"stats,omitempty"`
}

func (x *StatResponse) Reset() {
	*x = StatResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_msg_msg_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StatResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StatResponse) ProtoMessage() {}

func (x *StatResponse) ProtoReflect() protoreflect.Message {
	mi := &file_msg_msg_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StatResponse.ProtoReflect.Descriptor instead.
func (*StatResponse) Descriptor() ([]byte, []int) {
	return file_msg_msg_proto_rawDescGZIP(), []int{6}
}

func (x *StatResponse) GetError() string {
	if x != nil {
		return x.Error
	}
	return ""
}

func (x *StatResponse) GetStats() []byte {
	if x != nil {
		return x.Stats
	}
	return nil
}

type PingRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ping string `protobuf:"bytes,1,opt,name=ping,proto3" json:"ping,omitempty"`
}

func (x *PingRequest) Reset() {
	*x = PingRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_msg_msg_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PingRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PingRequest) ProtoMessage() {}

func (x *PingRequest) ProtoReflect() protoreflect.Message {
	mi := &file_msg_msg_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PingRequest.ProtoReflect.Descriptor instead.
func (*PingRequest) Descriptor() ([]byte, []int) {
	return file_msg_msg_proto_rawDescGZIP(), []int{7}
}

func (x *PingRequest) GetPing() string {
	if x != nil {
		return x.Ping
	}
	return ""
}

type PongResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Error              string `protobuf:"bytes,1,opt,name=error,proto3" json:"error,omitempty"`
	RegistryUpdateTime int64  `protobuf:"varint,2,opt,name=registryUpdateTime,proto3" json:"registryUpdateTime,omitempty"`
	Pong               string `protobuf:"bytes,3,opt,name=pong,proto3" json:"pong,omitempty"`
}

func (x *PongResponse) Reset() {
	*x = PongResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_msg_msg_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PongResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PongResponse) ProtoMessage() {}

func (x *PongResponse) ProtoReflect() protoreflect.Message {
	mi := &file_msg_msg_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PongResponse.ProtoReflect.Descriptor instead.
func (*PongResponse) Descriptor() ([]byte, []int) {
	return file_msg_msg_proto_rawDescGZIP(), []int{8}
}

func (x *PongResponse) GetError() string {
	if x != nil {
		return x.Error
	}
	return ""
}

func (x *PongResponse) GetRegistryUpdateTime() int64 {
	if x != nil {
		return x.RegistryUpdateTime
	}
	return 0
}

func (x *PongResponse) GetPong() string {
	if x != nil {
		return x.Pong
	}
	return ""
}

type Content struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id                 int32  `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	RegistryUpdateTime int64  `protobuf:"varint,2,opt,name=registryUpdateTime,proto3" json:"registryUpdateTime,omitempty"`
	BlockType          int32  `protobuf:"varint,3,opt,name=blockType,proto3" json:"blockType,omitempty"`
	Ip4                uint32 `protobuf:"varint,4,opt,name=ip4,proto3" json:"ip4,omitempty"`
	Domain             string `protobuf:"bytes,5,opt,name=domain,proto3" json:"domain,omitempty"`
	Url                string `protobuf:"bytes,6,opt,name=url,proto3" json:"url,omitempty"`
	Pack               []byte `protobuf:"bytes,7,opt,name=pack,proto3" json:"pack,omitempty"`
}

func (x *Content) Reset() {
	*x = Content{}
	if protoimpl.UnsafeEnabled {
		mi := &file_msg_msg_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Content) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Content) ProtoMessage() {}

func (x *Content) ProtoReflect() protoreflect.Message {
	mi := &file_msg_msg_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Content.ProtoReflect.Descriptor instead.
func (*Content) Descriptor() ([]byte, []int) {
	return file_msg_msg_proto_rawDescGZIP(), []int{9}
}

func (x *Content) GetId() int32 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *Content) GetRegistryUpdateTime() int64 {
	if x != nil {
		return x.RegistryUpdateTime
	}
	return 0
}

func (x *Content) GetBlockType() int32 {
	if x != nil {
		return x.BlockType
	}
	return 0
}

func (x *Content) GetIp4() uint32 {
	if x != nil {
		return x.Ip4
	}
	return 0
}

func (x *Content) GetDomain() string {
	if x != nil {
		return x.Domain
	}
	return ""
}

func (x *Content) GetUrl() string {
	if x != nil {
		return x.Url
	}
	return ""
}

func (x *Content) GetPack() []byte {
	if x != nil {
		return x.Pack
	}
	return nil
}

var File_msg_msg_proto protoreflect.FileDescriptor

var file_msg_msg_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x6d, 0x73, 0x67, 0x2f, 0x6d, 0x73, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x03, 0x6d, 0x73, 0x67, 0x22, 0x21, 0x0a, 0x09, 0x49, 0x44, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x14, 0x0a, 0x05, 0x71, 0x75, 0x65, 0x72, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04,
	0x52, 0x05, 0x71, 0x75, 0x65, 0x72, 0x79, 0x22, 0x22, 0x0a, 0x0a, 0x49, 0x50, 0x34, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x71, 0x75, 0x65, 0x72, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x71, 0x75, 0x65, 0x72, 0x79, 0x22, 0x22, 0x0a, 0x0a, 0x55,
	0x52, 0x4c, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x71, 0x75, 0x65,
	0x72, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x71, 0x75, 0x65, 0x72, 0x79, 0x22,
	0x25, 0x0a, 0x0d, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x14, 0x0a, 0x05, 0x71, 0x75, 0x65, 0x72, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x05, 0x71, 0x75, 0x65, 0x72, 0x79, 0x22, 0x7e, 0x0a, 0x0e, 0x53, 0x65, 0x61, 0x72, 0x63, 0x68,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f,
	0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x2e,
	0x0a, 0x12, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x79, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65,
	0x54, 0x69, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x12, 0x72, 0x65, 0x67, 0x69,
	0x73, 0x74, 0x72, 0x79, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x26,
	0x0a, 0x07, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x0c, 0x2e, 0x6d, 0x73, 0x67, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x52, 0x07, 0x72,
	0x65, 0x73, 0x75, 0x6c, 0x74, 0x73, 0x22, 0x23, 0x0a, 0x0b, 0x53, 0x74, 0x61, 0x74, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x71, 0x75, 0x65, 0x72, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x71, 0x75, 0x65, 0x72, 0x79, 0x22, 0x3a, 0x0a, 0x0c, 0x53,
	0x74, 0x61, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x65,
	0x72, 0x72, 0x6f, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f,
	0x72, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x74, 0x61, 0x74, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x05, 0x73, 0x74, 0x61, 0x74, 0x73, 0x22, 0x21, 0x0a, 0x0b, 0x50, 0x69, 0x6e, 0x67, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x69, 0x6e, 0x67, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x70, 0x69, 0x6e, 0x67, 0x22, 0x68, 0x0a, 0x0c, 0x50, 0x6f,
	0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x72,
	0x72, 0x6f, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72,
	0x12, 0x2e, 0x0a, 0x12, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x79, 0x55, 0x70, 0x64, 0x61,
	0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x12, 0x72, 0x65,
	0x67, 0x69, 0x73, 0x74, 0x72, 0x79, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65,
	0x12, 0x12, 0x0a, 0x04, 0x70, 0x6f, 0x6e, 0x67, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x70, 0x6f, 0x6e, 0x67, 0x22, 0xb7, 0x01, 0x0a, 0x07, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
	0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x02, 0x69, 0x64,
	0x12, 0x2e, 0x0a, 0x12, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x79, 0x55, 0x70, 0x64, 0x61,
	0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x12, 0x72, 0x65,
	0x67, 0x69, 0x73, 0x74, 0x72, 0x79, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65,
	0x12, 0x1c, 0x0a, 0x09, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x54, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x05, 0x52, 0x09, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x54, 0x79, 0x70, 0x65, 0x12, 0x10,
	0x0a, 0x03, 0x69, 0x70, 0x34, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x69, 0x70, 0x34,
	0x12, 0x16, 0x0a, 0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x12, 0x10, 0x0a, 0x03, 0x75, 0x72, 0x6c, 0x18,
	0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x75, 0x72, 0x6c, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x61,
	0x63, 0x6b, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x70, 0x61, 0x63, 0x6b, 0x32, 0xb1,
	0x02, 0x0a, 0x05, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x12, 0x2f, 0x0a, 0x08, 0x53, 0x65, 0x61, 0x72,
	0x63, 0x68, 0x49, 0x44, 0x12, 0x0e, 0x2e, 0x6d, 0x73, 0x67, 0x2e, 0x49, 0x44, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x13, 0x2e, 0x6d, 0x73, 0x67, 0x2e, 0x53, 0x65, 0x61, 0x72, 0x63,
	0x68, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x31, 0x0a, 0x09, 0x53, 0x65, 0x61,
	0x72, 0x63, 0x68, 0x49, 0x50, 0x34, 0x12, 0x0f, 0x2e, 0x6d, 0x73, 0x67, 0x2e, 0x49, 0x50, 0x34,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x13, 0x2e, 0x6d, 0x73, 0x67, 0x2e, 0x53, 0x65,
	0x61, 0x72, 0x63, 0x68, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x31, 0x0a, 0x09,
	0x53, 0x65, 0x61, 0x72, 0x63, 0x68, 0x55, 0x52, 0x4c, 0x12, 0x0f, 0x2e, 0x6d, 0x73, 0x67, 0x2e,
	0x55, 0x52, 0x4c, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x13, 0x2e, 0x6d, 0x73, 0x67,
	0x2e, 0x53, 0x65, 0x61, 0x72, 0x63, 0x68, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x37, 0x0a, 0x0c, 0x53, 0x65, 0x61, 0x72, 0x63, 0x68, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x12,
	0x12, 0x2e, 0x6d, 0x73, 0x67, 0x2e, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x13, 0x2e, 0x6d, 0x73, 0x67, 0x2e, 0x53, 0x65, 0x61, 0x72, 0x63, 0x68,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2b, 0x0a, 0x04, 0x53, 0x74, 0x61, 0x74,
	0x12, 0x10, 0x2e, 0x6d, 0x73, 0x67, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x11, 0x2e, 0x6d, 0x73, 0x67, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2b, 0x0a, 0x04, 0x50, 0x69, 0x6e, 0x67, 0x12, 0x10, 0x2e,
	0x6d, 0x73, 0x67, 0x2e, 0x50, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x11, 0x2e, 0x6d, 0x73, 0x67, 0x2e, 0x50, 0x6f, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x42, 0x22, 0x5a, 0x20, 0x67, 0x75, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x75, 0x73, 0x68, 0x65, 0x72, 0x32, 0x2f, 0x75, 0x32, 0x62, 0x79, 0x63, 0x6b, 0x64, 0x75,
	0x6d, 0x70, 0x2f, 0x6d, 0x73, 0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_msg_msg_proto_rawDescOnce sync.Once
	file_msg_msg_proto_rawDescData = file_msg_msg_proto_rawDesc
)

func file_msg_msg_proto_rawDescGZIP() []byte {
	file_msg_msg_proto_rawDescOnce.Do(func() {
		file_msg_msg_proto_rawDescData = protoimpl.X.CompressGZIP(file_msg_msg_proto_rawDescData)
	})
	return file_msg_msg_proto_rawDescData
}

var file_msg_msg_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_msg_msg_proto_goTypes = []interface{}{
	(*IDRequest)(nil),      // 0: msg.IDRequest
	(*IP4Request)(nil),     // 1: msg.IP4Request
	(*URLRequest)(nil),     // 2: msg.URLRequest
	(*DomainRequest)(nil),  // 3: msg.DomainRequest
	(*SearchResponse)(nil), // 4: msg.SearchResponse
	(*StatRequest)(nil),    // 5: msg.StatRequest
	(*StatResponse)(nil),   // 6: msg.StatResponse
	(*PingRequest)(nil),    // 7: msg.PingRequest
	(*PongResponse)(nil),   // 8: msg.PongResponse
	(*Content)(nil),        // 9: msg.Content
}
var file_msg_msg_proto_depIdxs = []int32{
	9, // 0: msg.SearchResponse.results:type_name -> msg.Content
	0, // 1: msg.Check.SearchID:input_type -> msg.IDRequest
	1, // 2: msg.Check.SearchIP4:input_type -> msg.IP4Request
	2, // 3: msg.Check.SearchURL:input_type -> msg.URLRequest
	3, // 4: msg.Check.SearchDomain:input_type -> msg.DomainRequest
	5, // 5: msg.Check.Stat:input_type -> msg.StatRequest
	7, // 6: msg.Check.Ping:input_type -> msg.PingRequest
	4, // 7: msg.Check.SearchID:output_type -> msg.SearchResponse
	4, // 8: msg.Check.SearchIP4:output_type -> msg.SearchResponse
	4, // 9: msg.Check.SearchURL:output_type -> msg.SearchResponse
	4, // 10: msg.Check.SearchDomain:output_type -> msg.SearchResponse
	6, // 11: msg.Check.Stat:output_type -> msg.StatResponse
	8, // 12: msg.Check.Ping:output_type -> msg.PongResponse
	7, // [7:13] is the sub-list for method output_type
	1, // [1:7] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_msg_msg_proto_init() }
func file_msg_msg_proto_init() {
	if File_msg_msg_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_msg_msg_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IDRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_msg_msg_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IP4Request); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_msg_msg_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*URLRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_msg_msg_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DomainRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_msg_msg_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SearchResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_msg_msg_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StatRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_msg_msg_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StatResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_msg_msg_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PingRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_msg_msg_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PongResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_msg_msg_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Content); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_msg_msg_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_msg_msg_proto_goTypes,
		DependencyIndexes: file_msg_msg_proto_depIdxs,
		MessageInfos:      file_msg_msg_proto_msgTypes,
	}.Build()
	File_msg_msg_proto = out.File
	file_msg_msg_proto_rawDesc = nil
	file_msg_msg_proto_goTypes = nil
	file_msg_msg_proto_depIdxs = nil
}
