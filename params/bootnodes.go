// Copyright 2015 The mesh-chain Authors
// This file is part of the mesh-chain library.
//
// The mesh-chain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The mesh-chain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the mesh-chain library. If not, see <http://www.gnu.org/licenses/>.

package params

var MainnetBootnodes = []string{}

var TestnetBootnodes = []string{
	"enode://2484c0c30993cd7b2fcdb0cdf897e49453b5a13439739039c87024904ff090be6862f64cea0b6a2b4748519c17355de49f48c3c3bee0f49683fab5a923e51d0b@43.138.2.80:44944",
}

var DevnetBootnodes = []string{}

var RinkebyBootnodes = []string{}

var RinkebyV5Bootnodes = []string{}

// DiscoveryV5Bootnodes are the enode URLs of the P2P bootstrap nodes for the
// experimental RLPx v5 topic-discovery network.
var DiscoveryV5Bootnodes = []string{}
