/*
 * Copyright (C) 2018 The ontology Authors
 * This file is part of The ontology library.
 *
 * The ontology is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ontology is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with The ontology.  If not, see <http://www.gnu.org/licenses/>.
 */

// Package restful privides restful server router
/*
* Copyright (C) 2020 The poly network Authors
* This file is part of The poly network library.
*
* The poly network is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* The poly network is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
* You should have received a copy of the GNU Lesser General Public License
* along with The poly network . If not, see <http://www.gnu.org/licenses/>.
*/
package restful

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/paxont/config"
	"github.com/paxont/http/types"
	"github.com/paxont/log"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const TLS_PORT int = 443

type ApiServer interface {
	Start() error
	Stop()
}

type handler func(map[string]interface{}) map[string]interface{}

type Action struct {
	sync.RWMutex
	Name    string
	Handler handler
}

type restServer struct {
	router       *Router
	cfg          *config.Server
	listener     net.Listener
	server       *http.Server
	responsePack ResponsePack
	postMap      map[string]Action //post method map
	getMap       map[string]Action //get method map
}

//init restful wallet interface server
func InitPaxontServer(netImplement PaxServiceInterface, cfg *config.Server) ApiServer {
	rt := &restServer{
		cfg: cfg,
	}

	rt.router = NewRouter()
	rt.getMap = make(map[string]Action)
	rt.postMap = make(map[string]Action)
	rt.responsePack = netImplement
	rt.registryServerAction(netImplement)
	rt.initGetHandler()
	rt.initPostHandler()
	return rt
}

func (this *restServer) registryServerAction(netImplement PaxServiceInterface) {
	this.getMap[types.GET_EVENTS] = Action{
		Name:    types.ACTION_GET_EVENTS,
		Handler: netImplement.QueryEvents,
	}
	this.getMap[types.GET_SIGNS] = Action{
		Name:    types.ACTION_GET_GET_SIGNS,
		Handler: netImplement.QuerySigns,
	}
	this.getMap[types.GET_RESULTS] = Action{
		Name:    types.ACTION_GET_RESULTS,
		Handler: netImplement.QueryResults,
	}
	this.getMap[types.GET_APPROVAL_LIST] = Action{
		Name:    types.ACTION_GET_APPROVAL_LIST,
		Handler: netImplement.QueryApprovals,
	}
	this.getMap[types.GET_WHITELIST] = Action{
		Name:    types.ACTION_GET_WHITELIST,
		Handler: netImplement.QueryWhiteList,
	}
	this.getMap[types.GET_ETH_HEIGHT] = Action{
		Name:    types.ACTION_GET_ETH_HEIGHT,
		Handler: netImplement.QueryEthHeight,
	}
	this.getMap[types.GET_ONT_HEIGHT] = Action{
		Name:    types.ACTION_GET_ONT_HEIGHT,
		Handler: netImplement.QueryOntHeight,
	}

	this.postMap[types.POST_ADD_WHITELIST] = Action{
		Name:    types.ACTION_ADD_WHITELIST,
		Handler: netImplement.AddWhiteList,
	}

	this.postMap[types.POST_UPDATE_WHITELIST] = Action{
		Name:    types.ACTION_UPDATE_WHITELIST,
		Handler: netImplement.UpdateWhiteList,
	}

	this.postMap[types.POST_DELETE_WHITELIST] = Action{
		Name:    types.ACTION_DELETE_WHITELIST,
		Handler: netImplement.DeleteWhiteList,
	}

	this.postMap[types.POST_PROCESS_APPROVAL_LIST] = Action{
		Name:    types.ACTION_POST_PROCESS_APPROVAL_LIST,
		Handler: netImplement.LockApprovals,
	}

	this.postMap[types.POST_CANCLE_APPROVAL_LIST] = Action{
		Name:    types.ACTION_POST_CANCLE_APPROVAL_LIST,
		Handler: netImplement.UnlockApprovals,
	}
	this.postMap[types.POST_VALIDATE_TX] = Action{
		Name:    types.ACTION_POST_VALIDATE_TX,
		Handler: netImplement.ValidateTx,
	}
	this.postMap[types.POST_ADD_APPROVAL] = Action{
		Name:    types.ACTION_POST_ADD_APPROVAL,
		Handler: netImplement.AddApproval,
	}
	//this.postMap[types.POST_RESET_EVENTS] = Action{
	//	Name:    types.ACTION_RESET_EVENTS,
	//	Handler: netImplement.ResetEvents,
	//}

}

//start server
func (this *restServer) Start() error {
	retPort := int(this.cfg.HttpRestPort)
	if retPort == 0 {
		log.Fatal("Not configure HttpRestPort port ")
		return nil
	}

	tlsFlag := false
	if tlsFlag || retPort%1000 == TLS_PORT {
		var err error
		this.listener, err = this.initTlsListen()
		if err != nil {
			log.Error("Https Cert: ", err.Error())
			return err
		}
	} else {
		var err error
		this.listener, err = net.Listen("tcp", ":"+strconv.Itoa(retPort))
		if err != nil {
			log.Fatal("net.Listen: ", err.Error())
			return err
		}
	}
	this.server = &http.Server{Handler: this.router}
	err := this.server.Serve(this.listener)

	if err != nil {
		log.Fatal("ListenAndServe: ", err.Error())
		return err
	}

	return nil
}

func (this *restServer) getPath(url string) string {
	return url
}

//get request params
func (this *restServer) getParams(r *http.Request, url string, req map[string]interface{}) map[string]interface{} {
	rawquery := r.URL.RawQuery
	if len(rawquery) > 0 {
		querys := strings.Split(rawquery, "&")
		for _, q := range querys {
			tmp := strings.Split(q, "=")
			key := tmp[0]
			val := tmp[1]
			req[key] = val
		}
	}

	return req
}

//init get Handler
func (this *restServer) initGetHandler() {

	for k := range this.getMap {
		this.router.Get(k, func(w http.ResponseWriter, r *http.Request) {

			var req = make(map[string]interface{})
			var resp map[string]interface{}

			url := this.getPath(r.URL.Path)
			if h, ok := this.getMap[url]; ok {
				req = this.getParams(r, url, req)
				resp = h.Handler(req)
			} else {
				resp = this.responsePack.PackResponse(INVALID_METHOD)
			}
			this.response(w, resp)
		})
	}
}

//init post Handler
func (this *restServer) initPostHandler() {
	for k := range this.postMap {
		this.router.Post(k, func(w http.ResponseWriter, r *http.Request) {

			body, _ := ioutil.ReadAll(r.Body)
			defer r.Body.Close()

			var req = make(map[string]interface{})
			var resp map[string]interface{}

			url := this.getPath(r.URL.Path)
			if h, ok := this.postMap[url]; ok {
				if err := json.Unmarshal(body, &req); err == nil {
					req = this.getParams(r, url, req)
					resp = h.Handler(req)
				} else {
					resp = this.responsePack.PackResponse(ILLEGAL_DATAFORMAT)
				}
			} else {
				resp = this.responsePack.PackResponse(INVALID_METHOD)
			}
			this.response(w, resp)
		})
	}
	//Options
	for k := range this.postMap {
		this.router.Options(k, func(w http.ResponseWriter, r *http.Request) {
			this.write(w, []byte{})
		})
	}

}
func (this *restServer) write(w http.ResponseWriter, data []byte) {
	w.Header().Add("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("content-type", "application/json;charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(data)
}

//response
func (this *restServer) response(w http.ResponseWriter, resp map[string]interface{}) {
	//resp["Desc"] = restful.ErrMap[resp["Error"].(uint32)]
	data, err := json.Marshal(resp)
	if err != nil {
		log.Fatalf("HTTP Handle - json.Marshal: %v", err)
		return
	}
	this.write(w, data)
}

//stop restful server
func (this *restServer) Stop() {
	if this.server != nil {
		this.server.Shutdown(context.Background())
		log.Error("Close restful ")
	}
}

//restart server
func (this *restServer) Restart(cmd map[string]interface{}) map[string]interface{} {
	go func() {
		time.Sleep(time.Second)
		this.Stop()
		time.Sleep(time.Second)
		go this.Start()
	}()

	var resp = this.responsePack.PackResponse(SUCCESS)
	return resp
}

//init tls
func (this *restServer) initTlsListen() (net.Listener, error) {

	certPath := this.cfg.HttpCertPath
	keyPath := this.cfg.HttpKeyPath
	// load cert
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Error("load keys fail", err)
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	restPort := strconv.Itoa(int(this.cfg.HttpRestPort))
	log.Info("TLS listen port is ", restPort)
	listener, err := tls.Listen("tcp", ":"+restPort, tlsConfig)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return listener, nil
}
