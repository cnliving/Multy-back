/*
Copyright 2017 Idealnaya rabota LLC
Licensed under Multy.io license.
See LICENSE for details
*/
package client

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Appscrunch/Multy-back/btc"
	"github.com/Appscrunch/Multy-back/currencies"
	"github.com/Appscrunch/Multy-back/store"
	"github.com/KristinaEtc/slf"
	"github.com/blockcypher/gobcy"

	"github.com/Appscrunch/Multy-back/eth"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/gin-gonic/gin"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"math/rand"
)

const (
	msgErrMissingRequestParams  = "missing request parametrs"
	msgErrServerError           = "internal server error"
	msgErrNoWallet              = "no such wallet"
	msgErrWalletNonZeroBalance  = "can't delete non zero balance wallet"
	msgErrWalletIndex           = "already existing wallet index"
	msgErrTxHistory             = "not found any transaction history"
	msgErrAddressIndex          = "already existing address index"
	msgErrMethodNotImplennted   = "method is not implemented"
	msgErrHeaderError           = "wrong authorization headers"
	msgErrRequestBodyError      = "missing request body params"
	msgErrUserNotFound          = "user not found in db"
	msgErrNoTransactionAddress  = "zero balance"
	msgErrNoSpendableOutputs    = "no spendable outputs"
	msgErrRatesError            = "internal server error rates"
	msgErrDecodeWalletIndexErr  = "wrong wallet index"
	msgErrNoSpendableOuts       = "no spendable outputs"
	msgErrDecodeCurIndexErr     = "wrong currency index"
	msgErrAdressBalance         = "empty address or 3-rd party server error"
	msgErrChainIsNotImplemented = "current chain is not implemented"
	msgErrUserHaveNoTxs         = "user have no transactions"
)

type RestClient struct {
	middlewareJWT *GinJWTMiddleware
	userStore     store.UserStore
	rpcClient     *rpcclient.Client
	// ballance api for test net
	apiBTCTest     gobcy.API
	btcConfTestnet BTCApiConf
	// ballance api for main net
	apiBTCMain     gobcy.API
	btcConfMainnet BTCApiConf
	//
	eth *ethereum.Client

	log slf.StructuredLogger
}

type BTCApiConf struct {
	Token, Coin, Chain string
}

func SetRestHandlers(
	ethClient *ethereum.Client,
	userDB store.UserStore,
	btcConfTest,
	btcConfMain BTCApiConf,
	r *gin.Engine,
	clientRPC *rpcclient.Client,
	btcNodeAddress string,
) (*RestClient, error) {
	restClient := &RestClient{
		userStore: userDB,
		rpcClient: clientRPC,

		btcConfTestnet: btcConfTest,
		btcConfMainnet: btcConfMain,

		apiBTCTest: gobcy.API{
			Token: btcConfTest.Token,
			Coin:  btcConfTest.Coin,
			Chain: btcConfTest.Chain,
		},
		apiBTCMain: gobcy.API{
			Token: btcConfMain.Token,
			Coin:  btcConfMain.Coin,
			Chain: btcConfMain.Chain,
		},
		eth: ethClient,
		log: slf.WithContext("rest-client"),
	}

	initMiddlewareJWT(restClient)

	r.POST("/auth", restClient.LoginHandler())
	r.GET("/server/config", restClient.getServerConfig())

	r.GET("/statuscheck", restClient.statusCheck())

	r.GET("/donations", restClient.getDonationsBalances())

	v1 := r.Group("/api/v1")
	v1.Use(restClient.middlewareJWT.MiddlewareFunc())
	{
		v1.POST("/wallet", restClient.addWallet())                                              //nothing to change
		v1.DELETE("/wallet/:currencyid/:walletindex", restClient.deleteWallet())                //todo add currency id √
		v1.POST("/address", restClient.addAddress())                                            //todo add currency id √
		v1.GET("/transaction/feerate/:currencyid", restClient.getFeeRate())                     //todo add currency id √
		v1.GET("/outputs/spendable/:currencyid/:addr", restClient.getSpendableOutputs())        //nothing to change	√
		v1.POST("/transaction/send/:currencyid", restClient.sendRawTransaction(btcNodeAddress)) //todo add currency id √
		v1.POST("/transaction/send", restClient.sendRawHDTransaction(btcNodeAddress))
		v1.GET("/wallet/:walletindex/verbose/:currencyid", restClient.getWalletVerbose())                   //todo add currency id √
		v1.GET("/wallets/verbose", restClient.getAllWalletsVerbose())                                       //nothing to change	√
		v1.GET("/wallets/transactions/:currencyid/:walletindex", restClient.getWalletTransactionsHistory()) //todo add currency id	√
		v1.POST("/wallet/name", restClient.changeWalletName())                                              //todo add currency id √
		v1.GET("/exchange/changelly/list", restClient.changellyListCurrencies())
		//v1.GET("/drop", restClient.drop())

	}
	return restClient, nil
}

func initMiddlewareJWT(restClient *RestClient) {
	restClient.middlewareJWT = &GinJWTMiddleware{
		Realm:      "test zone",
		Key:        []byte("secret key"), // config
		Timeout:    time.Hour,
		MaxRefresh: time.Hour,
		Authenticator: func(userId, deviceId, pushToken string, deviceType int, c *gin.Context) (store.User, bool) {
			query := bson.M{"userID": userId}

			user := store.User{}

			err := restClient.userStore.FindUser(query, &user)

			if err != nil || len(user.UserID) == 0 {
				return user, false
			}
			return user, true
		},
		Unauthorized: nil,
		TokenLookup:  "header:Authorization",

		TokenHeadName: "Bearer",

		TimeFunc: time.Now,
	}
}

type WalletParams struct {
	CurrencyID   int    `json:"currencyID"`
	Address      string `json:"address"`
	AddressIndex int    `json:"addressIndex"`
	WalletIndex  int    `json:"walletIndex"`
	WalletName   string `json:"walletName"`
}

type SelectWallet struct {
	CurrencyID   int    `json:"currencyID"`
	WalletIndex  int    `json:"walletIndex"`
	Address      string `json:"address"`
	AddressIndex int    `json:"addressIndex"`
}

type EstimationSpeeds struct {
	VerySlow int
	Slow     int
	Medium   int
	Fast     int
	VeryFast int
}

type Tx struct {
	Transaction   string `json:"transaction"`
	AllowHighFees bool   `json:"allowHighFees"`
}

type DisplayWallet struct {
	Chain    string          `json:"chain"`
	Adresses []store.Address `json:"addresses"`
}

type WalletExtended struct {
	CuurencyID  int         `bson:"chain"`       //cuurencyID
	WalletIndex int         `bson:"walletIndex"` //walletIndex
	Addresses   []AddressEx `bson:"addresses"`
}

type AddressEx struct { // extended
	AddressID int    `bson:"addressID"` //addressIndex
	Address   string `bson:"address"`
	Amount    int    `bson:"amount"` //float64
}

type Donation struct {
	/*
	Status
	0 - Pending
	1 - Active
	2 - Closed
	3 - Canceled
	 */


	FeatureID	int		`json:"id"`
	Address		string	`json:"address"`
	Amount		int64	`json:"amount"`
	Status 		int		`json:"status"`
}

func getToken(c *gin.Context) (string, error) {
	authHeader := strings.Split(c.GetHeader("Authorization"), " ")
	if len(authHeader) < 2 {
		return "", errors.New(msgErrHeaderError)
	}
	return authHeader[1], nil
}

func createCustomWallet(wp WalletParams, token string, restClient *RestClient, c *gin.Context) error {
	user := store.User{}
	query := bson.M{"devices.JWT": token}

	err := restClient.userStore.FindUser(query, &user)
	if err != nil {
		restClient.log.Errorf("deleteWallet: restClient.userStore.FindUser: %s\t[addr=%s]", err.Error(), c.Request.RemoteAddr)
		err = errors.New(msgErrUserNotFound)
		return err
	}
	for _, wallet := range user.Wallets {
		if wallet.CurrencyID == wp.CurrencyID && wallet.WalletIndex == wp.WalletIndex {
			err = errors.New(msgErrWalletIndex)
			return err
		}
	}
	wallet := createWallet(wp.CurrencyID, wp.Address, wp.AddressIndex, wp.WalletIndex, wp.WalletName)
	sel := bson.M{"devices.JWT": token}
	update := bson.M{"$push": bson.M{"wallets": wallet}}
	err = restClient.userStore.Update(sel, update)
	if err != nil {
		restClient.log.Errorf("addWallet: restClient.userStore.Update: %s\t[addr=%s]", err.Error(), c.Request.RemoteAddr)
		err := errors.New(msgErrServerError)
		return err
	}
	return nil

}

func changeName(cn ChangeName, token string, restClient *RestClient, c *gin.Context) error {
	user := store.User{}
	query := bson.M{"devices.JWT": token}

	if err := restClient.userStore.FindUser(query, &user); err != nil {
		restClient.log.Errorf("deleteWallet: restClient.userStore.FindUser: %s\t[addr=%s]", err.Error(), c.Request.RemoteAddr)
		err := errors.New(msgErrUserNotFound)
		return err
	}

	for _, wallet := range user.Wallets {
		if wallet.CurrencyID == cn.CurrencyID && wallet.WalletIndex == cn.WalletIndex {
			sel := bson.M{"userID": user.UserID, "wallets.walletIndex": cn.WalletIndex}
			update := bson.M{
				"$set": bson.M{
					"wallets.$.walletName": cn.WalletName,
				},
			}
			err := restClient.userStore.Update(sel, update)
			if err != nil {
				err := errors.New(msgErrServerError)
				return err
			}
			return nil
		}
	}

	err := errors.New(msgErrNoWallet)
	return err

}

func addAddressToWallet(address, token string, currencyID, walletIndex, addressIndex int, restClient *RestClient, c *gin.Context) error {
	user := store.User{}
	query := bson.M{"devices.JWT": token}

	if err := restClient.userStore.FindUser(query, &user); err != nil {
		restClient.log.Errorf("deleteWallet: restClient.userStore.FindUser: %s\t[addr=%s]", err.Error(), c.Request.RemoteAddr)
		err := errors.New(msgErrUserNotFound)
		return err
	}

	for _, wallet := range user.Wallets {
		if wallet.CurrencyID == currencyID && wallet.WalletIndex == walletIndex {
			for _, walletAddress := range wallet.Adresses {
				if walletAddress.AddressIndex == addressIndex {
					err := errors.New(msgErrAddressIndex)
					return err
				}
			}
		}
	}

	addr := store.Address{
		Address:        address,
		AddressIndex:   addressIndex,
		LastActionTime: time.Now().Unix(),
	}
	sel := bson.M{"devices.JWT": token, "wallets.walletIndex": walletIndex}
	update := bson.M{"$push": bson.M{"wallets.$.addresses": addr}}
	if err := restClient.userStore.Update(sel, update); err != nil {
		restClient.log.Errorf("addAddressToWallet: restClient.userStore.Update: %s\t[addr=%s]", err.Error(), c.Request.RemoteAddr)
		err := errors.New(msgErrServerError)
		return err
	}

	switch currencyID {
	case currencies.Bitcoin:
		go resyncBTCAddress(address, c.Request.RemoteAddr, restClient)
		restClient.log.Debugf("currencies.Biocoin: resyncBTCAddress: %s\t[addr=%s]", address, c.Request.RemoteAddr)
	case currencies.Ether:
		// TODO implement re-sync method
	default:

	}

	return nil

}

func (restClient *RestClient) getDonationsBalances() gin.HandlerFunc {
	return func(c *gin.Context) {
		resp := getFakeDonationBalances()

		c.JSON(http.StatusOK, resp)
	}
}



func (restClient *RestClient) drop() gin.HandlerFunc {
	return func(c *gin.Context) {
		restClient.userStore.DropTest()
	}
}

func (restClient *RestClient) addWallet() gin.HandlerFunc {
	return func(c *gin.Context) {

		token, err := getToken(c)
		if err != nil {
			restClient.log.Errorf("addWallet: getToken: %s\t[addr=%s]", err.Error(), c.Request.RemoteAddr)
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrHeaderError,
			})
			return
		}

		var (
			code    = http.StatusOK
			message = http.StatusText(http.StatusOK)
		)

		var wp WalletParams

		err = decodeBody(c, &wp)
		if err != nil {
			restClient.log.Errorf("addWallet: decodeBody: %s\t[addr=%s]", err.Error(), c.Request.RemoteAddr)
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrRequestBodyError,
			})
			return
		}

		switch wp.CurrencyID {
		case currencies.Bitcoin:
			err := createCustomWallet(wp, token, restClient, c)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"code":    http.StatusBadRequest,
					"message": err.Error(),
				})
				return
			}
			go resyncBTCAddress(wp.Address, c.Request.RemoteAddr, restClient)
		case currencies.Ether:
			err := createCustomWallet(wp, token, restClient, c)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"code":    http.StatusBadRequest,
					"message": err.Error(),
				})
				return
			}
			// TODO implement ethereum re-sync method
			// go resyncETHAddress(wp.Address, c.Request.RemoteAddr, restClient)
		default:
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    code,
				"message": msgErrMethodNotImplennted,
			})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"code":    code,
			"message": message,
		})
		return
	}
}

type ChangeName struct {
	WalletName  string `json:"walletname"`
	CurrencyID  int    `json:"currencyID"`
	WalletIndex int    `json:"walletIndex"`
}

func (restClient *RestClient) changeWalletName() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := getToken(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrHeaderError,
			})
			return
		}

		var cn ChangeName
		err = decodeBody(c, &cn)
		if err != nil {
			restClient.log.Errorf("changeWalletName: decodeBody: %s\t[addr=%s]", err.Error(), c.Request.RemoteAddr)
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrRequestBodyError,
			})
			return
		}
		err = changeName(cn, token, restClient, c)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"code":    http.StatusOK,
			"message": http.StatusText(http.StatusOK),
		})

	}
}

func (restClient *RestClient) statusCheck() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, `{"Status":"ok"}`)
	}
}

func (restClient *RestClient) getServerConfig() gin.HandlerFunc {
	return func(c *gin.Context) {
		resp := map[string]interface{}{
			"stockexchanges": map[string][]string{
				"poloniex": []string{"usd_btc", "eth_btc", "eth_usd", "btc_usd"},
				"gdax":     []string{"eur_btc", "usd_btc", "eth_btc", "eth_usd", "eth_eur", "btc_usd"},
			},
			"servertime": time.Now().Unix(),
			"api":        "0.01",
			"android": map[string]int{
				"soft": 1,
				"hard": 1,
			},
			"ios": map[string]int{
				"soft": 18,
				"hard": 1,
			},
			"donate": map[string]string{
				"BTC": "mzNZBhim9XGy66FkdzrehHwdWNgbiTYXCQ",
				"ETH": "0x54f46318d8f83c28b719ccf01ab4628e1e8f65fa",
			},
		}
		c.JSON(http.StatusOK, resp)
	}
}

func checkBTCAddressbalance(address string, restClient *RestClient) int64 {
	var balance int64
	query := bson.M{"address": address}
	spOuts, err := restClient.userStore.GetAddressSpendableOutputs(query)
	if err != nil {
		return balance
	}

	for _, out := range spOuts {
		balance += out.TxOutAmount
	}
	return balance
}

func getBTCAddressSpendableOutputs(address string, restClient *RestClient) []store.SpendableOutputs {
	query := bson.M{"address": address}
	spOuts, err := restClient.userStore.GetAddressSpendableOutputs(query)
	if err != nil && err != mgo.ErrNotFound {
		restClient.log.Errorf("getBTCAddressSpendableOutputs: GetAddressSpendableOutputs: %s\t", err.Error())
	}
	return spOuts
}

func (restClient *RestClient) deleteWallet() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := getToken(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrHeaderError,
			})
			return
		}

		walletIndex, err := strconv.Atoi(c.Param("walletindex"))
		restClient.log.Debugf("getWalletVerbose [%d] \t[walletindexr=%s]", walletIndex, c.Request.RemoteAddr)
		if err != nil {
			restClient.log.Errorf("getWalletVerbose: non int wallet index:[%d] %s \t[addr=%s]", walletIndex, err.Error(), c.Request.RemoteAddr)
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrDecodeWalletIndexErr,
			})
			return
		}

		currencyId, err := strconv.Atoi(c.Param("currencyid"))
		restClient.log.Debugf("getWalletVerbose [%d] \t[currencyId=%s]", walletIndex, c.Request.RemoteAddr)
		if err != nil {
			restClient.log.Errorf("getWalletVerbose: non int wallet index:[%d] %s \t[addr=%s]", walletIndex, err.Error(), c.Request.RemoteAddr)
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrDecodeCurIndexErr,
			})
			return
		}

		var (
			code    int
			message string
		)

		user := store.User{}
		query := bson.M{"devices.JWT": token}
		if err := restClient.userStore.FindUser(query, &user); err != nil {
			restClient.log.Errorf("deleteWallet: restClient.userStore.FindUser: %s\t[addr=%s]", err.Error(), c.Request.RemoteAddr)
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrUserNotFound,
			})
			return
		}
		code = http.StatusOK
		message = http.StatusText(http.StatusOK)

		switch currencyId {
		case currencies.Bitcoin:
			var totalBalance int64
			for _, wallet := range user.Wallets {
				if wallet.WalletIndex == walletIndex {
					for _, address := range wallet.Adresses {
						totalBalance += checkBTCAddressbalance(address.Address, restClient)
					}
				}
			}

			if totalBalance != 0 {
				c.JSON(http.StatusBadRequest, gin.H{
					"code":    http.StatusBadRequest,
					"message": msgErrWalletNonZeroBalance,
				})
				return
			}

			err := restClient.userStore.DeleteWallet(user.UserID, walletIndex)
			if err != nil {
				restClient.log.Errorf("deleteWallet: restClient.userStore.Update: %s\t[addr=%s]", err.Error(), c.Request.RemoteAddr)
				c.JSON(http.StatusBadRequest, gin.H{
					"code":    http.StatusBadRequest,
					"message": msgErrNoWallet,
				})
				return
			}
			code = http.StatusOK
			message = http.StatusText(http.StatusOK)

		case currencies.Ether:
			var totalBalance int64
			for _, wallet := range user.Wallets {
				if wallet.WalletIndex == walletIndex {
					for _, address := range wallet.Adresses {
						balance, err := restClient.eth.GetAddressBalance(address.Address)
						if err != nil {
							restClient.log.Errorf("deleteWallet: eth.GetAddressBalance: %s\t[addr=%s]", err.Error(), c.Request.RemoteAddr)
						}
						totalBalance += balance.Int64()
					}
				}
			}
			if totalBalance != 0 {
				c.JSON(http.StatusBadRequest, gin.H{
					"code":    http.StatusBadRequest,
					"message": msgErrWalletNonZeroBalance,
				})
				return
			}
			err := restClient.userStore.DeleteWallet(user.UserID, walletIndex)
			if err != nil {
				restClient.log.Errorf("deleteWallet: restClient.userStore.Update: %s\t[addr=%s]", err.Error(), c.Request.RemoteAddr)
				c.JSON(http.StatusBadRequest, gin.H{
					"code":    http.StatusBadRequest,
					"message": msgErrNoWallet,
				})
				return
			}
			code = http.StatusOK
			message = http.StatusText(http.StatusOK)
		default:
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrChainIsNotImplemented,
			})
			return
		}

		c.JSON(code, gin.H{
			"code":    code,
			"message": message,
		})

	}
}

func resyncBTCAddress(hash, RemoteAdd string, restClient *RestClient) {
	allResync := []resyncTx{}
	requestTimes := 0
	addrInfo, err := restClient.apiBTCTest.GetAddrFull(hash, map[string]string{"limit": "50"})
	if err != nil {
		restClient.log.Errorf("resyncAddress: restClient.apiBTCTest.GetAddrFull : %s \t[addr=%s]", err.Error(), RemoteAdd)
	}

	fmt.Println(addrInfo.TXs)

	if addrInfo.FinalNumTX > 50 {
		requestTimes = int(float64(addrInfo.FinalNumTX) / 50.0)
	}

	for _, tx := range addrInfo.TXs {
		allResync = append(allResync, resyncTx{
			hash:        tx.Hash,
			blockHeight: tx.BlockHeight,
		})
	}

	for i := 0; i < requestTimes; i++ {
		addrInfo, err := restClient.apiBTCTest.GetAddrFull(hash, map[string]string{"limit": "50", "before": strconv.Itoa(allResync[len(allResync)-1].blockHeight)})
		if err != nil {
			restClient.log.Errorf("resyncAddress: restClient.apiBTCTest.GetAddrFull: %s \t[addr=%s]", err.Error(), RemoteAdd)
		}
		for _, tx := range addrInfo.TXs {
			allResync = append(allResync, resyncTx{
				hash:        tx.Hash,
				blockHeight: tx.BlockHeight,
			})
		}
	}
	restClient.log.Errorf("\n\n allResync: %s , len(): %d\n\n", allResync, len(allResync))
	reverseResyncTx(allResync)

	for _, reTx := range allResync {
		txHash, err := chainhash.NewHashFromStr(reTx.hash)
		if err != nil {
			restClient.log.Errorf("resyncAddress: chainhash.NewHashFromStr = %s\t[addr=%s]", err, RemoteAdd)
		}
		rawTx, err := btc.GetRawTransactionVerbose(txHash)
		if err != nil {
			restClient.log.Errorf("resyncAddress: rpcClient.GetRawTransactionVerbose = %s\t[addr=%s]", err, RemoteAdd)
		}
		btc.ProcessTransaction(int64(reTx.blockHeight), rawTx)
	}
}
func reverseResyncTx(ss []resyncTx) {
	last := len(ss) - 1
	for i := 0; i < len(ss)/2; i++ {
		ss[i], ss[last-i] = ss[last-i], ss[i]
	}
}

type resyncTx struct {
	hash        string
	blockHeight int
}

func (restClient *RestClient) addAddress() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := getToken(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrHeaderError,
			})
			return
		}
		var sw SelectWallet
		err = decodeBody(c, &sw)
		if err != nil {
			restClient.log.Errorf("addAddress: decodeBody: %s\t[addr=%s]", err.Error(), c.Request.RemoteAddr)
		}

		err = addAddressToWallet(sw.Address, token, sw.CurrencyID, sw.WalletIndex, sw.AddressIndex, restClient, c)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusText(http.StatusBadRequest),
				"message": err.Error(),
			})
		}

		c.JSON(http.StatusCreated, gin.H{
			"code":    http.StatusText(http.StatusCreated),
			"message": "wallet created",
		})
	}
}

func (restClient *RestClient) getFeeRate() gin.HandlerFunc {
	return func(c *gin.Context) {
		var sp EstimationSpeeds
		currencyId, err := strconv.Atoi(c.Param("currencyid"))
		if err != nil {
			restClient.log.Errorf("getWalletVerbose: non int currency id: %s \t[addr=%s]", err.Error(), c.Request.RemoteAddr)
			c.JSON(http.StatusBadRequest, gin.H{
				"speeds":  sp,
				"code":    http.StatusBadRequest,
				"message": msgErrDecodeCurIndexErr,
			})
			return
		}

		switch currencyId {
		case currencies.Bitcoin:
			var rates []store.RatesRecord
			speeds := []int{
				1, 2, 3, 4, 5,
			}
			if err := restClient.userStore.GetAllRates("category", &rates); err != nil {
				c.JSON(http.StatusOK, gin.H{
					"speeds":  sp,
					"code":    http.StatusInternalServerError,
					"message": msgErrRatesError,
				})
			}

			sp = EstimationSpeeds{
				VerySlow: rates[speeds[0]].Category,
				Slow:     rates[speeds[1]].Category,
				Medium:   rates[speeds[2]].Category,
				Fast:     rates[speeds[3]].Category,
				VeryFast: rates[speeds[4]].Category,
			}
			c.JSON(http.StatusOK, gin.H{
				"speeds":  sp,
				"code":    http.StatusOK,
				"message": http.StatusText(http.StatusOK),
			})
		case currencies.Ether:

		default:

		}

	}
}

func (restClient *RestClient) getSpendableOutputs() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := getToken(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrHeaderError,
			})
			return
		}

		currencyID, err := strconv.Atoi(c.Param("currencyid"))
		restClient.log.Errorf("getSpendableOutputs [%d] \t[addr=%s]", currencyID, c.Request.RemoteAddr)
		if err != nil {
			restClient.log.Errorf("getSpendableOutputs: non int currencyID:[%d] %s \t[addr=%s]", currencyID, err.Error(), c.Request.RemoteAddr)
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrDecodeCurIndexErr,
				"outs":    0,
			})
			return
		}

		address := c.Param("addr")

		var (
			code    int
			message string
		)

		user := store.User{}
		query := bson.M{"devices.JWT": token}
		if err := restClient.userStore.FindUser(query, &user); err != nil {
			restClient.log.Errorf("getAllWalletsVerbose: restClient.userStore.FindUser: %s\t[addr=%s]", err.Error(), c.Request.RemoteAddr)
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrUserNotFound,
				"outs":    0,
			})
			return
		} else {
			code = http.StatusOK
			message = http.StatusText(http.StatusOK)
		}
		var spOuts []store.SpendableOutputs

		switch currencyID {
		case currencies.Bitcoin:

			//todo remove query
			query := bson.M{"userid": user.UserID, "transactions.txaddress": address}
			spOuts, err = restClient.userStore.GetAddressSpendableOutputs(query)
			if err != nil {
				restClient.log.Errorf("getSpendableOutputs: GetAddressSpendableOutputs:[%d] %s \t[addr=%s]", currencyID, err.Error(), c.Request.RemoteAddr)
			}

		default:
			code = http.StatusBadRequest
			message = msgErrMethodNotImplennted
		}

		c.JSON(code, gin.H{
			"code":    code,
			"message": message,
			"outs":    spOuts,
		})
	}
}

type RawHDTx struct {
	CurrencyID int `json:"currencyid"`
	Payload    `json:"payload"`
}

type Payload struct {
	Address      string `json:"address"`
	AddressIndex int    `json:"addressindex"`
	WalletIndex  int    `json:"walletindex"`
	Transaction  string `json:"transaction"`
	IsHD         bool   `json:"ishd"`
}

func (restClient *RestClient) sendRawHDTransaction(btcNodeAddress string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var rawTx RawHDTx
		if err := decodeBody(c, &rawTx); err != nil {
			c.JSON(http.StatusOK, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrRequestBodyError,
			})
		}

		token, err := getToken(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrHeaderError,
			})
			return
		}
		if rawTx.IsHD {
			err = addAddressToWallet(rawTx.Address, token, rawTx.CurrencyID, rawTx.WalletIndex, rawTx.AddressIndex, restClient, c)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"code":    http.StatusBadRequest,
					"message": err.Error(),
				})
				return
			}
		}

		switch rawTx.CurrencyID {
		case currencies.Bitcoin:
			connCfg := &rpcclient.ConnConfig{
				Host:         btcNodeAddress,
				User:         "multy",
				Pass:         "multy",
				HTTPPostMode: true,  // Bitcoin core only supports HTTP POST mode
				DisableTLS:   false, // Bitcoin core does not provide TLS by default
				Certificates: []byte(btc.Cert),
			}

			client, err := rpcclient.New(connCfg, nil)
			if err != nil {
				restClient.log.Errorf("sendRawTransaction: rpcclient.New  \t[addr=%s]", err, c.Request.RemoteAddr)
			}
			defer client.Shutdown()

			txid, err := client.SendCyberRawTransaction(rawTx.Transaction, true)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"code":    http.StatusBadRequest,
					"message": err.Error(),
				})
			} else {
				c.JSON(http.StatusOK, gin.H{
					"code":            http.StatusOK,
					"message":         http.StatusText(http.StatusOK),
					"TransactionHash": txid,
				})
			}
		case currencies.Ether:

			hash, err := restClient.eth.SendRawTransaction(rawTx.Transaction)
			if err != nil {
				restClient.log.Errorf("sendRawHDTransaction:eth.SendRawTransaction %s", err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{
					"code":    http.StatusInternalServerError,
					"message": err.Error(),
				})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"code":    http.StatusOK,
				"message": hash,
			})
			return
		default:
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrChainIsNotImplemented,
			})
		}
	}
}
func (restClient *RestClient) sendRawTransaction(btcNodeAddress string) gin.HandlerFunc {
	return func(c *gin.Context) {

		currencyID, err := strconv.Atoi(c.Param("currencyid"))
		if err != nil {
			restClient.log.Errorf("getSpendableOutputs: non int currencyID:[%d] %s \t[addr=%s]", currencyID, err.Error(), c.Request.RemoteAddr)
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrDecodeCurIndexErr,
				"outs":    0,
			})
			return
		}

		switch currencyID {
		case currencies.Bitcoin:
			restClient.log.Infof("btc.Cert=%s\n", btc.Cert)

			connCfg := &rpcclient.ConnConfig{
				Host:         btcNodeAddress,
				User:         "multy",
				Pass:         "multy",
				HTTPPostMode: true,  // Bitcoin core only supports HTTP POST mode
				DisableTLS:   false, // Bitcoin core does not provide TLS by default
				Certificates: []byte(btc.Cert),
			}
			// Notice the notification parameter is nil since notifications are
			// not supported in HTTP POST mode.
			client, err := rpcclient.New(connCfg, nil)
			if err != nil {
				restClient.log.Errorf("sendRawTransaction: rpcclient.New  \t[addr=%s]", err, c.Request.RemoteAddr)
			}
			defer client.Shutdown()

			var rawTx RawTx

			decodeBody(c, &rawTx)
			txid, err := client.SendCyberRawTransaction(rawTx.Transaction, true)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"code":    http.StatusBadRequest,
					"message": err.Error(),
				})
			} else {
				c.JSON(http.StatusOK, gin.H{
					"TransactionHash": txid,
				})
			}
		case currencies.Ether:
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrChainIsNotImplemented,
			})
		default:
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrChainIsNotImplemented,
			})
		}
	}
}

type RawTx struct { // remane RawClientTransaction
	Transaction string `json:"transaction"` //HexTransaction
}

func (restClient *RestClient) getWalletVerbose() gin.HandlerFunc {
	return func(c *gin.Context) {
		var wv []WalletVerbose
		token, err := getToken(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrHeaderError,
			})
			return
		}

		walletIndex, err := strconv.Atoi(c.Param("walletindex"))
		restClient.log.Debugf("getWalletVerbose [%d] \t[walletindexr=%s]", walletIndex, c.Request.RemoteAddr)
		if err != nil {
			restClient.log.Errorf("getWalletVerbose: non int wallet index:[%d] %s \t[addr=%s]", walletIndex, err.Error(), c.Request.RemoteAddr)
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrDecodeWalletIndexErr,
				"wallet":  wv,
			})
			return
		}

		var (
			code    int
			message string
		)
		user := store.User{}
		query := bson.M{"devices.JWT": token, "wallets.walletIndex": walletIndex}

		if err := restClient.userStore.FindUser(query, &user); err != nil {
			restClient.log.Errorf("getAllWalletsVerbose: restClient.userStore.FindUser: %s\t[addr=%s]", err.Error(), c.Request.RemoteAddr)
			c.JSON(code, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrUserNotFound,
				"wallet":  wv,
			})
			return
		}

		currencyId, err := strconv.Atoi(c.Param("currencyid"))
		restClient.log.Debugf("getWalletVerbose [%d] \t[currencyId=%s]", walletIndex, c.Request.RemoteAddr)
		if err != nil {
			restClient.log.Errorf("getWalletVerbose: non int currency id:[%d] %s \t[addr=%s]", currencyId, err.Error(), c.Request.RemoteAddr)
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrDecodeCurIndexErr,
			})
			return
		}

		switch currencyId {
		case currencies.Bitcoin:
			code = http.StatusOK
			message = http.StatusText(http.StatusOK)

			var av []AddressVerbose

			for _, wallet := range user.Wallets {
				if wallet.WalletIndex == walletIndex { // specify wallet index

					for _, address := range wallet.Adresses {
						spOuts := getBTCAddressSpendableOutputs(address.Address, restClient)
						av = append(av, AddressVerbose{
							LastActionTime: address.LastActionTime,
							Address:        address.Address,
							AddressIndex:   address.AddressIndex,
							Amount:         int(checkBTCAddressbalance(address.Address, restClient)),
							SpendableOuts:  spOuts,
						})
					}
					wv = append(wv, WalletVerbose{
						WalletIndex:    wallet.WalletIndex,
						CurrencyID:     wallet.CurrencyID,
						WalletName:     wallet.WalletName,
						LastActionTime: wallet.LastActionTime,
						DateOfCreation: wallet.DateOfCreation,
						VerboseAddress: av,
					})
					av = []AddressVerbose{}
				}

			}
		case currencies.Ether:
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrChainIsNotImplemented,
			})
			return
		default:
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrChainIsNotImplemented,
			})
			return
		}

		c.JSON(code, gin.H{
			"code":    code,
			"message": message,
			"wallet":  wv,
		})
	}
}

type WalletVerbose struct {
	CurrencyID     int              `json:"currencyid"`
	WalletIndex    int              `json:"walletindex"`
	WalletName     string           `json:"walletname"`
	LastActionTime int64            `json:"lastactiontime"`
	DateOfCreation int64            `json:"dateofcreation"`
	VerboseAddress []AddressVerbose `json:"addresses"`
}
type AddressVerbose struct {
	LastActionTime int64                    `json:"lastActionTime"`
	Address        string                   `json:"address"`
	AddressIndex   int                      `json:"addressindex"`
	Amount         int                      `json:"amount"`
	SpendableOuts  []store.SpendableOutputs `json:"spendableoutputs"`
}

type StockExchangeRate struct {
	ExchangeName   string `json:"exchangename"`
	FiatEquivalent int    `json:"fiatequivalent"`
	TotalAmount    int    `json:"totalamount"`
}

type TopIndex struct {
	CurrencyID int `json:"currencyid"`
	TopIndex   int `json:"topindex"`
}

func findTopIndexes(wallets []store.Wallet) []TopIndex {
	top := map[int]int{} // currency id -> topindex
	topIndex := []TopIndex{}
	for _, wallet := range wallets {
		top[wallet.CurrencyID]++
	}
	for currencyid, topindex := range top {
		topIndex = append(topIndex, TopIndex{
			CurrencyID: currencyid,
			TopIndex:   topindex,
		})
	}
	return topIndex
}

func fetchUndeletedWallets(wallets []store.Wallet) []store.Wallet {
	okWallets := []store.Wallet{}
	for _, wallet := range wallets {
		if wallet.Status == store.WalletStatusOK {
			okWallets = append(okWallets, wallet)
		}
	}
	return okWallets
}

func (restClient *RestClient) getAllWalletsVerbose() gin.HandlerFunc {
	return func(c *gin.Context) {
		var wv []WalletVerbose
		token, err := getToken(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrHeaderError,
			})
			return
		}
		var (
			code    int
			message string
		)
		user := store.User{}
		query := bson.M{"devices.JWT": token}

		if err := restClient.userStore.FindUser(query, &user); err != nil {
			restClient.log.Errorf("getAllWalletsVerbose: restClient.userStore.FindUser: %s\t[addr=%s]", err.Error(), c.Request.RemoteAddr)
			c.JSON(code, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrUserNotFound,
				"wallets": wv,
			})
			return
		}

		topIndexes := findTopIndexes(user.Wallets)

		code = http.StatusOK
		message = http.StatusText(http.StatusOK)

		var av []AddressVerbose

		okWallets := fetchUndeletedWallets(user.Wallets)

		for _, wallet := range okWallets {
			for _, address := range wallet.Adresses {
				spout := getBTCAddressSpendableOutputs(address.Address, restClient)
				fmt.Println(spout)
				av = append(av, AddressVerbose{
					LastActionTime: address.LastActionTime,
					Address:        address.Address,
					AddressIndex:   address.AddressIndex,
					Amount:         int(checkBTCAddressbalance(address.Address, restClient)),
					SpendableOuts:  spout,
				})
			}
			wv = append(wv, WalletVerbose{
				WalletIndex:    wallet.WalletIndex,
				CurrencyID:     wallet.CurrencyID,
				WalletName:     wallet.WalletName,
				LastActionTime: wallet.LastActionTime,
				DateOfCreation: wallet.DateOfCreation,
				VerboseAddress: av,
			})
			av = []AddressVerbose{}

		}

		c.JSON(code, gin.H{
			"code":       code,
			"message":    message,
			"wallets":    wv,
			"topindexes": topIndexes,
		})

	}
}

func (restClient *RestClient) getWalletTransactionsHistory() gin.HandlerFunc {
	return func(c *gin.Context) {
		var walletTxs []store.MultyTX
		token, err := getToken(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrHeaderError,
			})
			return
		}

		walletIndex, err := strconv.Atoi(c.Param("walletindex"))
		restClient.log.Debugf("getWalletVerbose [%d] \t[walletindexr=%s]", walletIndex, c.Request.RemoteAddr)
		if err != nil {
			restClient.log.Errorf("getWalletVerbose: non int wallet index:[%d] %s \t[addr=%s]", walletIndex, err.Error(), c.Request.RemoteAddr)
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrDecodeWalletIndexErr,
				"history": walletTxs,
			})
			return
		}

		user := store.User{}
		sel := bson.M{"devices.JWT": token}
		err = restClient.userStore.FindUser(sel, &user)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrUserNotFound,
				"history": walletTxs,
			})
			return
		}

		currencyId, err := strconv.Atoi(c.Param("currencyid"))
		restClient.log.Debugf("getWalletVerbose [%d] \t[currencyId=%s]", currencyId, c.Request.RemoteAddr)
		if err != nil {
			restClient.log.Errorf("getWalletVerbose: non int currency id:[%d] %s \t[addr=%s]", currencyId, err.Error(), c.Request.RemoteAddr)
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrDecodeCurIndexErr,
			})
			return
		}

		// txHistory := []TxHistory{}
		switch currencyId {
		case currencies.Bitcoin:
			query := bson.M{"userid": user.UserID}
			userTxs := []store.MultyTX{}
			err = restClient.userStore.GetAllWalletTransactions(query, &userTxs)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"code":    http.StatusBadRequest,
					"message": msgErrTxHistory,
					"history": walletTxs,
				})
				return
			}

			for _, tx := range userTxs {
				//New Logic
				var isTheSameWallet = false
				for _, input := range tx.WalletsInput {
					if walletIndex == input.WalletIndex {
						isTheSameWallet = true
					}
				}
				for _, output := range tx.WalletsOutput {
					if walletIndex == output.WalletIndex {
						isTheSameWallet = true
					}
				}

				if isTheSameWallet {
					walletTxs = append(walletTxs, tx)
				}
			}

		case currencies.Ether:
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrChainIsNotImplemented,
				"history": walletTxs,
			})
			return
		default:
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": msgErrChainIsNotImplemented,
				"history": walletTxs,
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"code":    http.StatusOK,
			"message": http.StatusText(http.StatusOK),
			"history": walletTxs,
		})
	}
}

type TxHistory struct {
	TxID        string               `json:"txid"`
	TxHash      string               `json:"txhash"`
	TxOutScript string               `json:"txoutscript"`
	TxAddress   string               `json:"address"`
	TxStatus    int                  `json:"txstatus"`
	TxOutAmount int64                `json:"txoutamount"`
	TxOutID     int                  `json:"txoutid"`
	WalletIndex int                  `json:"walletindex"`
	BlockTime   int64                `json:"blocktime"`
	BlockHeight int64                `json:"blockheight"`
	TxFee       int64                `json:"txfee"`
	MempoolTime int64                `json:"mempooltime"`
	BtcToUsd    float64              `json:"btctousd"`
	TxInputs    []store.AddresAmount `json:"txinputs"`
	TxOutputs   []store.AddresAmount `json:"txoutputs"`
}

func (restClient *RestClient) changellyListCurrencies() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiUrl := "https://api.changelly.com"
		apiKey := "8015e09ba78243ad889db470ec48fed4"
		apiSecret := "712bfcf899dd235b0af1d66922d5962e8c85a909635f838688a38b5f12c4d03a"
		cr := ChangellyReqest{
			JsonRpc: "2.0",
			ID:      1,
			Method:  "getCurrencies",
			Params:  []string{},
		}
		bs, err := json.Marshal(cr)
		if err != nil {
			restClient.log.Errorf("changellyListCurrencies: json.Marshal: %s \t[addr=%s]", err.Error(), c.Request.RemoteAddr)
			//
			return
		}

		sign := ComputeHmac512(bs, apiSecret)
		req, err := http.NewRequest("GET", apiUrl, nil)
		if err != nil {
			restClient.log.Errorf("changellyListCurrencies: http.NewRequest: %s \t[addr=%s]", err.Error(), c.Request.RemoteAddr)
			//
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("api-key", apiKey)
		req.Header.Set("sign", sign)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			restClient.log.Errorf("changellyListCurrencies: http.Client.Do: %s \t[addr=%s]", err.Error(), c.Request.RemoteAddr)
			//
			return
		}
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		c.JSON(http.StatusOK, gin.H{
			"code":    resp.StatusCode,
			"message": string(body),
		})

	}
}

func ComputeHmac512(message []byte, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha512.New, key)
	h.Write(message)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

type ChangellyReqest struct {
	JsonRpc string   `json:"jsonrpc"`
	ID      int      `json:"id"`
	Method  string   `json:"method"`
	Params  []string `json:"params"`
}



func getFakeDonationBalances() []Donation{
	donations := []Donation{}

	//Android
	donations = append(donations, Donation{10000, "1FPv9f8EGRDNod7mSvJnUFonUioA3Pw5ng", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10100, "1EyoGcD8sWzHikPPiJmzGiHyUyTHZzHtGU", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10101, "1Eo3U9PVSr3XyFhaH5sm1hWNpMmk1bCKQR", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10102, "1LtLD3W2uqABssS1SZxeYi75xvpZpYFZ1B", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10103, "14REwuBJQTTEF8PNCF2vmKtanoK7u1NbHr", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10104, "1DVmNPZgSUmdsBd5cmYUMgvmFH7rmDzyRY", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10105, "17wvEWAqnY5qmitVzTR9DiV8jPz3GK8GD1", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10106, "12bfndjvvj6FeXPN29Q16zvFxYZRR9zxQ4", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10107, "1Fp9JeCdcrz9ankvbktXiiQNtb55ZcBN3t", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10108, "1MtBFKke5JUJHYhxEt1NLzNtyiJTPvM5oX", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10109, "18LUgSbx5ugbAUCJoHwoymtMgvwjh6qr9Y", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10110, "1Ctw3VrQUvSiSRQrrRMpaAEuoBiwZP6HnU", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10111, "14BaepJbbLb6Dwe2Xk8A2QTmon3txgcbZf", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10200, "1NsjWawSRS7vgTjkYgRDMfsmSkjbmbDsrg", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10201, "1ChaYAgqzBMiwFKHk52CJf7TKxHGKcScDy", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10202, "1KqPGUb8eT2uP1UAwRvNuk2b4UgxXa3Sc9", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10203, "1Gjk2tkBi42o9TAen9VEWWNoDkYf5L9qgC", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10300, "1PXWUeabhszE71ND4fTFA6s4CqihKf4QVd", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10301, "17Tnp8H6m3mqWExQD3gAX9HSYwvuMSLoWG", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10302, "1PzdBkuL9RjnLhSgAh4So5ZkpSjti6jjs9", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10400, "16Ys7ARTJNaw1DqikX5ufjJbo7kdG3jUXj", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10401, "16qEnyvofjqnRupPd8kARzsNbavauVHoSj", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10402, "198RLNrbvomzEe54T5zvfqibpM8BWMJqvh", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10403, "1D3nrQ1PoBjpCAvGqzBEQguYDTeuYi53yu", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10404, "19ui7qnsfk8x64b6sArBUs7Zag4fwdBZjR", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10405, "1MgNGDvasvnoyHLMLE5fivNKEzkNB7mxBp", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10406, "15oBGfmAUeUAhYrKpZuax5wXaFM5f5ziET", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10407, "1AqYfNpPP3QysShKkYWEFMJQ8oMhi5p7J2", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10408, "1Eqse35Q9E3a8e8meibBFUTp426ymTuusR", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{10409, "164DrBqBmw4Xsj2Cbs2AQWiGGBoKDCvQF4", rand.Int63n(100000000), rand.Intn(5)})

	//IOS
	donations = append(donations, Donation{20000, "1GQsE1gBf3bjVACVve5R3aFgxiTAVgZReU", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20100, "1PwXHW2tKKBu6VfdmTmaFVbfpkHphVHVNu", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20101, "12iWkYPbwVXovtMUxhbXU6NBm4FcLV2Pbc", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20102, "1A5USPtadqSzZ7gydT8MzP6SxvdjBkRPzk", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20103, "125RMxikYSVZLM9b3fjN1PYQtav62yFd4H", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20104, "1PYCkHG3f5s8iMuHVDerRZZhuZUPuYf1jC", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20105, "1MwoexrY3TBej3JsGhudCEQ97mn8WKen7o", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20106, "1B2jT1bwzUP7pHfXNVFVGGZxsTidbo6kdT", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20107, "15PEDxaAUzoMKpbSeHHF5HWHcyN4wsptKs", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20108, "1BgRcp6tb6YUCsSNVDFvzZNU7pZmiuiqL9", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20109, "1FZ9eeWwcHcioJnixdr6Q7SroUcaCQVAN8", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20110, "1RSrQTwobtrYweK5r6Pkvy4BFgL1Mz7c8", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20111, "1FnYG1V8Nh2E3vjdSnXgbadzMDa1JKLHx5", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20200, "1AuZJdi1BU5BUFzEAd5SLbEYCaRvrsUZc6", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20201, "13ixZSo48m3vvGvw594ePRpRsBetDuWvAi", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20202, "13pBbAVozYJmdzTbKx66YMyx9Q8pLaxDFS", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20203, "1EmG7HV1d9fqnXC9d2omN1zXrcSnNDjS4z", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20300, "18n2RGk6JMH4hrGBaJmwoVVKqr2ZfdMJcK", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20301, "19i9o6HJkr7bRepnJc7eNPEPAv7KR9xaSb", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20302, "15t1LfPrZnv6cVtgPEJS8vr1sG1Sum5UQt", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20400, "1FjtcprdPSo2BVyUtPKqYmVKFH7aPNmMEE", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20401, "17Xkm8wxGoz8pWqWHC88qLXdFfB2qBuYJR", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20402, "1338kXwBoUMEQk6PZa9ThCbxjDE3DFKr5V", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20403, "12Nz3sAUzX6RUddcCujyoY9HtNz7GijMR9", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20404, "14WP9s82WBRZSf9bXy9Q9wenhcfFfPDjWr", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20405, "1BqmhJacEYvtpWBpq5HYeDTTETbKDL9ocx", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20406, "1B5FFAqtKPy9TyyFZwGQWAt6wmvGQ3qMNA", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20407, "1wxFYCSsxWHt82hByKfDsu7QH3KHwxqJX", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20408, "1KL6BneRs16Rt2V3iYwip2MgvS8UfCV8z5", rand.Int63n(100000000), rand.Intn(5)})
	donations = append(donations, Donation{20409, "1KbRaapwNnTJMZcpbTQfb7xJnymKFJDyC1", rand.Int63n(100000000), rand.Intn(5)})

	return donations
}