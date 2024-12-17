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
}

type btHeaderMarshaling struct {
	ExtraData  hexutil.Bytes
	Number     *math.HexOrDecimal256
	BlockScore *math.HexOrDecimal256
	GasUsed    math.HexOrDecimal64
	Timestamp  *math.HexOrDecimal256
}

func (t *BlockTest) Run() error {
	config, ok := Forks[t.json.Network]
	if !ok {
		return UnsupportedForkError{t.json.Network}
	}

	blockchain.InitDeriveSha(config)
	// import pre accounts & construct test genesis block & state root
	db := database.NewMemoryDBManager()
	_, err := t.genesis(config).Commit(common.Hash{}, db)
	if err != nil {
		fmt.Printf("FIXME:t.genesis(config).Commit(common.Hash{}, db) err=%s\n", err)
		return err
	}
	// if gblock.Hash() != t.json.Genesis.Hash {
	// 	return fmt.Errorf("genesis block hash doesn't match test: computed=%x, test=%x", gblock.Hash().Bytes()[:6], t.json.Genesis.Hash[:6])
	// }
	// if gblock.Root() != t.json.Genesis.StateRoot {
	// 	return fmt.Errorf("genesis block state root does not match test: computed=%x, test=%x", gblock.Root().Bytes()[:6], t.json.Genesis.StateRoot[:6])
	// }

	// TODO-Kaia: Replace gxhash with istanbul
	chain, err := blockchain.NewBlockChain(db, nil, config, gxhash.NewShared(), vm.Config{})
	if err != nil {
		fmt.Printf("FIXME: blockchain.NewBlockChain err=%s\n", err)
		return err
	}
	defer chain.Stop()

	validBlocks, err := t.insertBlocks(chain)
	if err != nil {
		fmt.Printf("FIXME: t.insertBlocks(chain) err=%s\n", err)
		return err
	}
	cmlast := chain.CurrentBlock().Hash()
	if common.Hash(t.json.BestBlock) != cmlast {
		return fmt.Errorf("FIXME: last block hash validation mismatch: want: %x, have: %x", t.json.BestBlock, cmlast)
	}
	newDB, err := chain.State()
	if err != nil {
		fmt.Printf("FIXME: chain.State() err=%s\n", err)
		return err
	}
	if err = t.validatePostState(newDB); err != nil {
		return fmt.Errorf("FIXME: post state validation failed: %v", err)
	}
	return t.validateImportedHeaders(chain, validBlocks)
}

func (t *BlockTest) genesis(config *params.ChainConfig) *blockchain.Genesis {
	return &blockchain.Genesis{
		Config:     config,
		Timestamp:  t.json.Genesis.Timestamp.Uint64(),
		ParentHash: t.json.Genesis.ParentHash,
		ExtraData:  t.json.Genesis.ExtraData,
		GasUsed:    t.json.Genesis.GasUsed,
		BlockScore: t.json.Genesis.BlockScore,
		Alloc:      t.json.Pre,
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
	converter := NewEthereumTestConverter(blockchain.Config())
	// insert the test blocks, which will execute all transactions
	for _, b := range t.json.Blocks {
		ethBlock, err := b.decode()
		if err != nil {
			if b.BlockHeader == nil {
				continue // OK - block is supposed to be invalid, continue with next block
			} else {
				return nil, fmt.Errorf("Block RLP decoding failed when expected to succeed: %v", err)
			}
		}
		// RLP decoding worked, try to insert into chain:
		kaiaBlock := converter.ConvertBlock(ethBlock)
		blocks := types.Blocks{kaiaBlock}
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
		if err = validateHeader(b.BlockHeader, kaiaBlock.Header()); err != nil {
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

func (bb *btBlock) decode() (*types.Block, error) {
	if len(bb.Rlp) == 0 {
		return nil, errMissingRLP
	}

	data, err := hexutil.Decode(bb.Rlp)
	if err != nil {
		return nil, fmt.Errorf("could not decode RLP: %v", err)
	}

	var eb ethBlock

	if err := rlp.DecodeBytes(data, &eb); err != nil {
		return nil, fmt.Errorf("could not decode block from RLP: %v", err)
	}

	header := &types.Header{
		ParentHash:  eb.Header.ParentHash,
		Root:        eb.Header.Root,
		TxHash:      eb.Header.TxHash,
		ReceiptHash: eb.Header.ReceiptHash,
		Bloom:       eb.Header.Bloom,
		Number:      new(big.Int).Set(eb.Header.Number),
		GasUsed:     eb.Header.GasUsed,
		Time:        new(big.Int).SetUint64(eb.Header.Time),
		Extra:       make([]byte, len(eb.Header.Extra)),
		BlockScore:  new(big.Int).Set(eb.Header.Difficulty),
	}

	copy(header.Extra, eb.Header.Extra)

	header.Rewardbase = common.Address{}
	header.Vote = []byte{}
	header.Governance = []byte{}
	header.TimeFoS = 0

	if eb.Header.BaseFee != nil {
		header.BaseFee = new(big.Int).Set(eb.Header.BaseFee)
	}

	if eb.Header.Difficulty != nil {
		header.BlockScore = new(big.Int).Set(eb.Header.Difficulty)
	} else {
		header.BlockScore = new(big.Int)
	}

	return types.NewBlock(header, eb.Transactions, nil), nil
}

var (
	errMissingRLP = fmt.Errorf("block rlp is missing")
)

type ethWithdrawal struct {
	Index     uint64
	Validator uint64
	Address   common.Address
	Amount    uint64
}

type ethBlock struct {
	Header       *ethHeader
	Transactions []*types.Transaction
	Uncles       []*ethHeader
	Withdrawals  []*ethWithdrawal `rlp:"optional"`
}

type ethHeader struct {
	ParentHash       common.Hash
	UncleHash        common.Hash
	Coinbase         common.Address
	Root             common.Hash
	TxHash           common.Hash
	ReceiptHash      common.Hash
	Bloom            types.Bloom
	Difficulty       *big.Int
	Number           *big.Int
	GasLimit         uint64
	GasUsed          uint64
	Time             uint64
	Extra            []byte
	MixDigest        common.Hash
	Nonce            [8]byte
	BaseFee          *big.Int
	WithdrawalsHash  *common.Hash `rlp:"optional"`
	BlobGasUsed      *uint64      `rlp:"optional"`
	ExcessBlobGas    *uint64      `rlp:"optional"`
	ParentBeaconRoot *common.Hash `rlp:"optional"`
	RequestsHash     *common.Hash `rlp:"optional"`
}

// EthereumTestConverter converts Ethereum test data to Kaia format
type EthereumTestConverter struct {
	config *params.ChainConfig
}

// NewEthereumTestConverter creates a new test converter
func NewEthereumTestConverter(config *params.ChainConfig) *EthereumTestConverter {
	return &EthereumTestConverter{
		config: config,
	}
}

// ConvertBlockHeader converts Ethereum header to Kaia header format
func (e *EthereumTestConverter) ConvertBlockHeader(eth *btHeader) *types.Header {
	header := &types.Header{
		ParentHash:  eth.ParentHash,
		Root:        eth.StateRoot,
		TxHash:      eth.TransactionsTrie,
		ReceiptHash: eth.ReceiptTrie,
		Bloom:       eth.Bloom,
		Number:      new(big.Int).Set(eth.Number),
		GasUsed:     eth.GasUsed,
		Time:        new(big.Int).Set(eth.Timestamp), // Use correct Timestamp field
		Extra:       make([]byte, len(eth.ExtraData)),
		BlockScore:  new(big.Int).Set(eth.BlockScore),
	}

	copy(header.Extra, eth.ExtraData)

	// Add Kaia specific fields with default values
	header.Rewardbase = common.Address{}
	header.Vote = []byte{}
	header.Governance = []byte{}
	header.TimeFoS = 0

	return header
}

// ConvertBlock converts Ethereum block for test validation
func (e *EthereumTestConverter) ConvertBlock(block *types.Block) *types.Block {
	if block == nil {
		return nil
	}

	header := block.Header()
	kaiaHeader := &types.Header{
		ParentHash:  header.ParentHash,
		Root:        header.Root,
		TxHash:      header.TxHash,
		ReceiptHash: header.ReceiptHash,
		Bloom:       header.Bloom,
		Number:      new(big.Int).Set(header.Number),
		GasUsed:     header.GasUsed,
		Time:        new(big.Int).SetUint64(header.Time.Uint64()),
		Extra:       make([]byte, len(header.Extra)),
		BlockScore:  new(big.Int).Set(header.BlockScore),
		Rewardbase:  common.Address{},
		Vote:        []byte{},
		Governance:  []byte{},
	}

	copy(kaiaHeader.Extra, header.Extra)

	// Only copy BaseFee if we're post-Magma fork
	if e.config.IsMagmaForkEnabled(header.Number) && header.BaseFee != nil {
		kaiaHeader.BaseFee = new(big.Int).Set(header.BaseFee)
	}

	return types.NewBlock(kaiaHeader, block.Transactions(), nil)
}

// ConvertGenesis converts Ethereum genesis to Kaia genesis format
func (e *EthereumTestConverter) ConvertGenesis(eth *blockchain.Genesis) *blockchain.Genesis {
	genesis := &blockchain.Genesis{
		Config:     e.config,
		Timestamp:  eth.Timestamp,
		ExtraData:  make([]byte, len(eth.ExtraData)),
		GasUsed:    eth.GasUsed,
		Number:     eth.Number,
		ParentHash: eth.ParentHash,
		BlockScore: eth.BlockScore,
		Alloc:      eth.Alloc,
	}

	copy(genesis.ExtraData, eth.ExtraData)

	// Set up governance if needed
	if e.config.Governance != nil {
		genesis.Governance = blockchain.SetGenesisGovernance(genesis)
	}

	return genesis
}
