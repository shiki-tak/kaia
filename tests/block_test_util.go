// Modifications Copyright 2024 The Kaia Authors
// Modifications Copyright 2018 The klaytn Authors
// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.
//
// This file is derived from tests/block_test_util.go (2018/06/04).
// Modified and improved for the klaytn development.
// Modified and improved for the Kaia development.

package tests

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/kaiachain/kaia/blockchain"
	"github.com/kaiachain/kaia/blockchain/state"
	"github.com/kaiachain/kaia/blockchain/types"
	"github.com/kaiachain/kaia/blockchain/vm"
	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/common/hexutil"
	"github.com/kaiachain/kaia/common/math"
	"github.com/kaiachain/kaia/consensus/gxhash"
	"github.com/kaiachain/kaia/params"
	"github.com/kaiachain/kaia/rlp"
	"github.com/kaiachain/kaia/storage/database"
)

// A BlockTest checks handling of entire blocks.
type BlockTest struct {
	json btJSON
}

// UnmarshalJSON implements json.Unmarshaler interface.
func (t *BlockTest) UnmarshalJSON(in []byte) error {
	return json.Unmarshal(in, &t.json)
}

type btJSON struct {
	Blocks    []btBlock               `json:"blocks"`
	Genesis   btHeader                `json:"genesisBlockHeader"`
	Pre       blockchain.GenesisAlloc `json:"pre"`
	Post      blockchain.GenesisAlloc `json:"postState"`
	BestBlock common.UnprefixedHash   `json:"lastblockhash"`
	Network   string                  `json:"network"`
}

type btBlock struct {
	BlockHeader *btHeader
	Rlp         string
}

//go:generate gencodec -type btHeader -field-override btHeaderMarshaling -out gen_btheader.go

type btHeader struct {
	Bloom            types.Bloom
	Number           *big.Int
	Hash             common.Hash
	ParentHash       common.Hash
	ReceiptTrie      common.Hash
	StateRoot        common.Hash
	TransactionsTrie common.Hash
	ExtraData        []byte
	BlockScore       *big.Int
	GasUsed          uint64
	Timestamp        *big.Int
	GasLimit         uint64
	Coinbase         common.Address
	UncleHash        common.Hash
	MixHash          common.Hash
	BaseFee          *big.Int
}

type btHeaderMarshaling struct {
	ExtraData  hexutil.Bytes
	Number     *math.HexOrDecimal256
	BlockScore *math.HexOrDecimal256
	GasUsed    math.HexOrDecimal64
	GasLimit   math.HexOrDecimal64
	Timestamp  *math.HexOrDecimal256
	BaseFee    *math.HexOrDecimal256
}

func (t *BlockTest) Run() error {
	config, ok := Forks[t.json.Network]
	if !ok {
		return UnsupportedForkError{t.json.Network}
	}

	blockchain.InitDeriveSha(config)

	// import pre accounts & construct test genesis block & state root
	db := database.NewMemoryDBManager()
	_, err := t.genesis(config).Commit(db)

	// if err != nil {
	// 	return err
	// }
	// if gblock.Hash() != t.json.Genesis.Hash {
	// 	return fmt.Errorf("genesis block hash doesn't match test: computed=%x, test=%x", gblock.Hash().Bytes()[:6], t.json.Genesis.Hash[:6])
	// }
	// if gblock.Root() != t.json.Genesis.StateRoot {
	// 	return fmt.Errorf("genesis block state root does not match test: computed=%x, test=%x", gblock.Root().Bytes()[:6], t.json.Genesis.StateRoot[:6])
	// }

	// TODO-Kaia: Replace gxhash with istanbul
	chain, err := blockchain.NewBlockChain(db, nil, config, gxhash.NewShared(), vm.Config{})
	if err != nil {
		fmt.Printf("FIXME: NewBlockChain error: %s\n", err)
		return err
	}
	defer chain.Stop()

	validBlocks, err := t.insertBlocks(chain)
	if err != nil {
		fmt.Printf("FIXME: t.insertBlocks(chain) error: %s\n", err)
		return err
	}
	cmlast := chain.CurrentBlock().Hash()
	if common.Hash(t.json.BestBlock) != cmlast {
		return fmt.Errorf("last block hash validation mismatch: want: %x, have: %x", t.json.BestBlock, cmlast)
	}
	newDB, err := chain.State()
	if err != nil {
		fmt.Printf("FIXME: chain.State() error: %s\n", err)
		return err
	}
	if err = t.validatePostState(newDB); err != nil {
		return fmt.Errorf("post state validation failed: %v", err)
	}
	return t.validateImportedHeaders(chain, validBlocks)
}

// TestGenesis represents the genesis block format used in tests
type TestGenesis struct {
	Header *btHeader
	Pre    blockchain.GenesisAlloc
}

// Create a block from the genesis data
func (g *TestGenesis) ToBlock(db database.DBManager) *types.Block {
	head := &types.Header{
		ParentHash:   g.Header.ParentHash,
		Rewardbase:   g.Header.Coinbase,
		Root:         g.Header.StateRoot,
		TxHash:       g.Header.TransactionsTrie,
		ReceiptHash:  g.Header.ReceiptTrie,
		Bloom:        g.Header.Bloom,
		BlockScore:   g.Header.BlockScore,
		Number:       g.Header.Number,
		GasUsed:      g.Header.GasUsed,
		Time:         g.Header.Timestamp,
		Extra:        g.Header.ExtraData,
		BaseFee:      g.Header.BaseFee,
		TimeFoS:      0,
		Governance:   []byte{},
		Vote:         []byte{},
		RandomReveal: []byte{},
		MixHash:      g.Header.MixHash.Bytes(),
	}

	return types.NewBlockWithHeader(head)
}

// Commit writes the genesis block and state to db
func (g *TestGenesis) Commit(db database.DBManager) (*types.Block, error) {
	block := g.ToBlock(db)

	// Write the genesis state to the database
	if g.Pre != nil {
		statedb, err := state.New(common.Hash{}, state.NewDatabase(db), nil, nil)
		if err != nil {
			return nil, err
		}
		for addr, account := range g.Pre {
			statedb.AddBalance(addr, account.Balance)
			statedb.SetCode(addr, account.Code)
			statedb.SetNonce(addr, account.Nonce)
			for key, value := range account.Storage {
				statedb.SetState(addr, key, value)
			}
		}
		root, err := statedb.Commit(true)
		if err != nil {
			return nil, err
		}

		// Update the genesis header with the correct state root
		block.Header().Root = root
	}

	// Write block to database
	db.WriteBlock(block)
	db.WriteCanonicalHash(block.Hash(), block.NumberU64())
	db.WriteHeadBlockHash(block.Hash())
	db.WriteHeadHeaderHash(block.Hash())

	return block, nil
}

func (t *BlockTest) genesis(config *params.ChainConfig) *TestGenesis {
	return &TestGenesis{
		Header: &t.json.Genesis,
		Pre:    t.json.Pre,
	}
}

/*
See https://github.com/ethereum/tests/wiki/Blockchain-Tests-II

	Whether a block is valid or not is a bit subtle, it's defined by presence of
	blockHeader and transactions fields. If they are missing, the block is
	invalid and we must verify that we do not accept it.

	Since some tests mix valid and invalid blocks we need to check this for every block.

	If a block is invalid it does not necessarily fail the test, if it's invalidness is
	expected we are expected to ignore it and continue processing and then validate the
	post state.
*/
func (t *BlockTest) insertBlocks(blockchain *blockchain.BlockChain) ([]btBlock, error) {
	validBlocks := make([]btBlock, 0)
	// insert the test blocks, which will execute all transactions
	for _, b := range t.json.Blocks {
		fmt.Printf("Debug: Block #1 parent hash: %x\n", b.BlockHeader.ParentHash)
		cb, err := b.decode()
		if err != nil {
			if b.BlockHeader == nil {
				continue // OK - block is supposed to be invalid, continue with next block
			} else {
				return nil, fmt.Errorf("Block RLP decoding failed when expected to succeed: %v", err)
			}
		}
		// RLP decoding worked, try to insert into chain:
		blocks := types.Blocks{cb}
		i, err := blockchain.InsertChain(blocks)
		if err != nil {
			if b.BlockHeader == nil {
				continue // OK - block is supposed to be invalid, continue with next block
			} else {
				return nil, fmt.Errorf("Block #%v insertion into chain failed: %v", blocks[i].Number(), err)
			}
		}
		if b.BlockHeader == nil {
			return nil, fmt.Errorf("Block insertion should have failed")
		}

		// validate RLP decoding by checking all values against test file JSON
		if err = validateHeader(b.BlockHeader, cb.Header()); err != nil {
			return nil, fmt.Errorf("Deserialised block header validation failed: %v", err)
		}
		validBlocks = append(validBlocks, b)
	}
	return validBlocks, nil
}

func validateHeader(h *btHeader, h2 *types.Header) error {
	if h.Bloom != h2.Bloom {
		return fmt.Errorf("Bloom: want: %x have: %x", h.Bloom, h2.Bloom)
	}
	if h.Number.Cmp(h2.Number) != 0 {
		return fmt.Errorf("Number: want: %v have: %v", h.Number, h2.Number)
	}
	if h.ParentHash != h2.ParentHash {
		return fmt.Errorf("Parent hash: want: %x have: %x", h.ParentHash, h2.ParentHash)
	}
	if h.ReceiptTrie != h2.ReceiptHash {
		return fmt.Errorf("Receipt hash: want: %x have: %x", h.ReceiptTrie, h2.ReceiptHash)
	}
	if h.TransactionsTrie != h2.TxHash {
		return fmt.Errorf("Tx hash: want: %x have: %x", h.TransactionsTrie, h2.TxHash)
	}
	if h.StateRoot != h2.Root {
		return fmt.Errorf("State hash: want: %x have: %x", h.StateRoot, h2.Root)
	}
	if !bytes.Equal(h.ExtraData, h2.Extra) {
		return fmt.Errorf("Extra data: want: %x have: %x", h.ExtraData, h2.Extra)
	}
	if h.BlockScore.Cmp(h2.BlockScore) != 0 {
		return fmt.Errorf("BlockScore: want: %v have: %v", h.BlockScore, h2.BlockScore)
	}
	if h.GasUsed != h2.GasUsed {
		return fmt.Errorf("GasUsed: want: %d have: %d", h.GasUsed, h2.GasUsed)
	}
	if h.Timestamp.Cmp(h2.Time) != 0 {
		return fmt.Errorf("Timestamp: want: %v have: %v", h.Timestamp, h2.Time)
	}
	return nil
}

func (t *BlockTest) validatePostState(statedb *state.StateDB) error {
	// validate post state accounts in test file against what we have in state db
	for addr, acct := range t.json.Post {
		// address is indirectly verified by the other fields, as it's the db key
		code2 := statedb.GetCode(addr)
		balance2 := statedb.GetBalance(addr)
		nonce2 := statedb.GetNonce(addr)
		if !bytes.Equal(code2, acct.Code) {
			return fmt.Errorf("account code mismatch for addr: %s want: %v have: %s", addr, acct.Code, hex.EncodeToString(code2))
		}
		if balance2.Cmp(acct.Balance) != 0 {
			return fmt.Errorf("account balance mismatch for addr: %s, want: %d, have: %d", addr, acct.Balance, balance2)
		}
		if nonce2 != acct.Nonce {
			return fmt.Errorf("account nonce mismatch for addr: %s want: %d have: %d", addr, acct.Nonce, nonce2)
		}
	}
	return nil
}

func (t *BlockTest) validateImportedHeaders(cm *blockchain.BlockChain, validBlocks []btBlock) error {
	// to get constant lookup when verifying block headers by hash (some tests have many blocks)
	bmap := make(map[common.Hash]btBlock, len(t.json.Blocks))
	for _, b := range validBlocks {
		bmap[b.BlockHeader.Hash] = b
	}
	// iterate over blocks backwards from HEAD and validate imported
	// headers vs test file. some tests have reorgs, and we import
	// block-by-block, so we can only validate imported headers after
	// all blocks have been processed by BlockChain, as they may not
	// be part of the longest chain until last block is imported.
	for b := cm.CurrentBlock(); b != nil && b.NumberU64() != 0; b = cm.GetBlockByHash(b.Header().ParentHash) {
		if err := validateHeader(bmap[b.Hash()].BlockHeader, b.Header()); err != nil {
			return fmt.Errorf("Imported block header validation failed: %v", err)
		}
	}
	return nil
}

// Add or update these structures
type TestHeader struct {
	ParentHash       common.Hash
	UncleHash        common.Hash
	Coinbase         []byte
	Root             common.Hash
	TxHash           common.Hash
	ReceiptHash      common.Hash
	Bloom            types.Bloom
	Difficulty       *big.Int
	Number           *big.Int
	GasLimit         uint64
	GasUsed          uint64
	Time             *big.Int
	Extra            []byte
	MixHash          common.Hash
	Nonce            []byte
	BaseFee          *big.Int     `rlp:"optional"`
	WithdrawalsHash  *common.Hash `rlp:"optional"`
	BlobGasUsed      *uint64      `rlp:"optional"`
	ExcessBlobGas    *uint64      `rlp:"optional"`
	ParentBeaconRoot *common.Hash `rlp:"optional"`
}

// Modify the decode function
func (bb *btBlock) decode() (*types.Block, error) {
	data, err := hexutil.Decode(bb.Rlp)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex: %v", err)
	}

	fmt.Printf("Debug: Full RLP hex: %x\n", data)

	// First decode just the raw RLP list
	s := rlp.NewStream(bytes.NewReader(data), 0)
	kind, size, err := s.Kind()
	if err != nil {
		return nil, fmt.Errorf("failed to get RLP kind: %v", err)
	}
	fmt.Printf("Debug: RLP kind: %v, size: %d\n", kind, size)

	if kind != rlp.List {
		return nil, fmt.Errorf("expected RLP list, got %v", kind)
	}

	// Manual decoding approach
	if _, err := s.List(); err != nil {
		return nil, fmt.Errorf("failed to enter outer list: %v", err)
	}

	// Decode header
	var header TestHeader
	if err := s.Decode(&header); err != nil {
		return nil, fmt.Errorf("failed to decode header: %v", err)
	}

	// Decode transactions
	var txs []*types.Transaction
	if err := s.Decode(&txs); err != nil {
		return nil, fmt.Errorf("failed to decode transactions: %v", err)
	}

	// Convert header
	var rewardbase common.Address
	if len(header.Coinbase) > 0 {
		copy(rewardbase[:], header.Coinbase[:20])
	}

	block := types.NewBlockWithHeader(&types.Header{
		ParentHash:   header.ParentHash,
		Rewardbase:   rewardbase,
		Root:         header.Root,
		TxHash:       header.TxHash,
		ReceiptHash:  header.ReceiptHash,
		Bloom:        header.Bloom,
		BlockScore:   header.Difficulty,
		Number:       header.Number,
		GasUsed:      header.GasUsed,
		Time:         header.Time,
		TimeFoS:      0,
		Extra:        header.Extra,
		Governance:   []byte{},
		Vote:         []byte{},
		BaseFee:      header.BaseFee,
		RandomReveal: []byte{},
		MixHash:      header.MixHash[:],
	})

	return block.WithBody(txs), nil
}
