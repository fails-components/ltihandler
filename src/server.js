/*
    Fails Components (Fancy Automated Internet Lecture System - Components)
    Copyright (C)  2015-2017 (original FAILS), 
                   2021- (FAILS Components)  Marten Richter <marten.richter@freenet.de>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import express from 'express'
import * as redis from 'redis'
import MongoClient from 'mongodb'
import { FailsJWTSigner } from 'fails-components-security'
import { FailsConfig } from 'fails-components-config'

// import { v4 as uuidv4, validate as isUUID } from 'uuid';
import { LtiHandler } from './ltihandler.js'

const initServer = async () => {
  const cfg = new FailsConfig()
  const redisclient = redis.createClient({
    detect_buffers: true /* required by notescreen connection */
  })

  const mongoclient = await MongoClient.connect(cfg.getMongoURL(), {
    useNewUrlParser: true,
    useUnifiedTopology: true
  })
  const mongodb = mongoclient.db(cfg.getMongoDB())

  const appsecurity = new FailsJWTSigner({
    redis: redisclient,
    type: 'app',
    expiresIn: '1m',
    secret: cfg.getKeysSecret()
  })

  const lmsList = cfg.getLmsList()

  const ltihandler = new LtiHandler({
    lmslist: lmsList,
    signJwt: appsecurity.signToken,
    redis: redisclient,
    mongo: mongodb,
    basefailsurl: cfg.getURL('appweb')
  })

  const app = express()

  // may be move the io also inside the object, on the other hand, I can not insert middleware anymore

  /* var ioIns = new Server(server,{cors: {
  origin: "http://192.168.1.116:3000",
  methods: ["GET", "POST"],
 // credentials: true
}}); */

  app.use(express.urlencoded({ extended: true }))
  app.use(express.json())

  console.log('debug path ', cfg.getSPath('lti') + '/launch')
  app.all(cfg.getSPath('lti') + '/launch', (req, res) => {
    return ltihandler.handleLaunch(req, res)
  })

  app.all(cfg.getSPath('lti') + '/login', (req, res) => {
    return ltihandler.handleLogin(req, res)
  })

  /*
// old test code?
app.all("/auth",function(req,res,next) {
  // console.log("Request:", req.token);
  // console.log("Res:",res);
   console.log("req.query auth",req.query);
   console.log("req.body auth",req.body);
   res.send('Hello LTI');
 });
 */

  app.listen(cfg.getPort('lti'), cfg.getHost(), function () {
    console.log(
      'Failsserver lti handler listening port:',
      cfg.getPort('lti'),
      ' host:',
      cfg.getHost()
    )
  })
}
initServer()
