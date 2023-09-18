/*
Package proto contains wire definitions of messages passed between nodes.
*/
//go:generate protoc -I=. --go_out=. --go_opt=paths=source_relative cosigner_service/shamir.proto
//go:generate protoc -I=. --go_out=. --go_opt=paths=source_relative raft_service/raft.proto
package proto
