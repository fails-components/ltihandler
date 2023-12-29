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

import { v4 as uuidv4, validate } from 'uuid'
import url from 'fast-url-parser'
import jwt from 'jsonwebtoken'
import { expressjwt as jwtexpress } from 'express-jwt'
import got from 'got'
import Jwk from 'rasha'
import moment from 'moment'

export class LtiHandler {
  constructor(args) {
    this.lmslist = args.lmslist
    this.redis = args.redis
    this.mongo = args.mongo
    this.signJwt = args.signJwt
    this.basefailsurl = args.basefailsurl
    this.coursewhitelist = args.coursewhitelist
    this.onlyLearners = args.onlyLearners

    console.log('ltihandler available lms ', args.lmslist)
    if (this.onlyLearners)
      console.log('all access limited to learner level for instructors')
  }

  handleLogin(req, res) {
    // console.log("Request:", req);
    // console.log("Res:",res);
    const params = { ...req.body }
    if (!params.iss || !params.login_hint || !params.target_link_uri)
      return res.status(400).send({
        status: 400,
        error: 'Bad Request',
        details: { message: 'no login parameters' }
      })

    console.log(
      'login request from',
      params.iss,
      'with client id',
      params.client_id
    ) // may be remove later
    const platform = this.lmslist[params.iss]
    if (!platform)
      return res.status(400).send({
        status: 400,
        error: 'Platform ' + params.iss + ' not registered!'
      })
    // use client_id for getting data base connection
    // if not active platform redirect

    const query = {
      response_type: 'id_token',
      response_mode: 'form_post',
      id_token_signed_response_alg: 'RS256',
      scope: 'openid',
      client_id: params.client_id,
      redirect_uri: params.target_link_uri,
      login_hint: params.login_hint,
      nonce: uuidv4(),
      prompt: 'none'
      /// state: "blabla"  // ok we do not need this, since nothing is bound to an account in this system
      // the lti is our authentification system, and identifies the user, so there is no access to our system
      // on which we have to keep track
      // it would be something else, if we require the user to login to our system first...
    }
    if (params.lti_message_hint)
      query.lti_message_hint = params.lti_message_hint
    if (params.lti_deployment_id)
      query.lti_deployment_id = params.lti_deployment_id
    res.redirect(
      url.format({
        pathname: platform.auth_request_url,
        query: query
      })
    )
  }

  async handleLaunch(req, res) {
    // console.log("Request:", req);
    // console.log("Res:",res);
    if (req.body.error) {
      return res.send('LMS reported error: ' + req.body.error_description)
    }
    if (req.body.id_token) {
      const decodedToken = jwt.decode(req.body.id_token, { complete: true })
      const platform = this.lmslist[decodedToken.payload.iss]
      if (!platform)
        return res.status(400).send({
          status: 400,
          error: 'Bad Request',
          details: {
            message:
              'platform' +
              decodedToken.payload.iss +
              ' not registered/supported'
          }
        })
      let keyinfo
      try {
        keyinfo = await got.get(platform.keyset_url).json()
      } catch (error) {
        console.log('lti error, key fetch', error)
        return res
          .status(400)
          .send({ status: 400, error: 'problem, while accessing platform key' })
      }
      const keys = keyinfo.keys
      if (!keys)
        return res.status(400).send({ status: 400, error: 'Keyset not found' })

      if (!decodedToken.header.kid)
        return res.status(400).send({ status: 400, error: 'no valid kid!' })

      const jwk = keys.find((key) => {
        return key.kid === decodedToken.header.kid
      })
      if (!jwk)
        return res.status(400).send({ status: 400, error: 'key not found' })
      let key
      try {
        key = await Jwk.export({ jwk: jwk })
      } catch (error) {
        console.log('Jwk export: error', error)
        return res
          .status(500)
          .send({ status: 400, error: 'key export problem' })
      }
      const payload = decodedToken.payload

      // console.log("decoded token payload",payload);
      if (!validate(payload.nonce))
        return res
          .status(400)
          .send({ status: 400, error: 'nonce wrong format' })
      let redres
      try {
        redres = await this.redis.exists('lti:nonce:' + payload.nonce)
      } catch (error) {
        console.log('lti error, redis', error)
        return res.status(400).send({ status: 400, error: 'redis broken' })
      }
      if (redres === 1)
        return res
          .status(400)
          .send({ status: 400, error: 'nonce reused, replay attack?' })
      else {
        // we have to store it in the db
        try {
          await this.redis.set('lti:nonce:' + payload.nonce, 'dummy', {
            EX: 60 * 10 /* 10 minutes */
          }) // we do not have to use the callback
        } catch (error) {
          console.log('lti error, redis', error)
          return res.status(400).send({ status: 400, error: 'redis broken' })
        }

        if (
          !jwt.verify(req.body.id_token, key, {
            /* nonce: ADD */
          })
        )
          return res
            .status(400)
            .send({ status: 400, error: 'jwt verification failure' })

        if (
          payload['https://purl.imsglobal.org/spec/lti/claim/message_type'] !==
          'LtiResourceLinkRequest'
        )
          return res.status(400).send({
            status: 400,
            error:
              'so far only resource links are supported ' +
              payload['https://purl.imsglobal.org/spec/lti/claim/message_type']
          })

        // now we have to collect the data
        const userinfo = {
          firstnames: payload.given_name,
          lastname: payload.family_name,
          displayname: payload.name,
          email: payload.email, // can be used for matching persons, multple possible
          lmssub: payload.sub // even this may be missing in anonymus case
        }
        if (payload['https://purl.imsglobal.org/spec/lti/claim/ext'])
          userinfo.lmsusername =
            payload[
              'https://purl.imsglobal.org/spec/lti/claim/ext'
            ].user_username

        // console.log("userinfo", userinfo);
        const lmscontext = {
          // TODO add unique platform identifier?
          ret_url:
            payload[
              'https://purl.imsglobal.org/spec/lti/claim/launch_presentation'
            ].return_url,
          iss: payload.iss, // not optional, use for identification

          /* aud: payload.aud, */ // may be exclude
          platform_id:
            payload['https://purl.imsglobal.org/spec/lti/claim/tool_platform']
              .guid, // optional
          deploy_id:
            payload['https://purl.imsglobal.org/spec/lti/claim/deployment_id'], // do not use for identification, period!
          course_id:
            payload['https://purl.imsglobal.org/spec/lti/claim/context'].id, // optional, use for context identification if possible
          resource_id:
            payload['https://purl.imsglobal.org/spec/lti/claim/resource_link']
              .id // use for identification
        }
        if (
          this.coursewhitelist &&
          (!lmscontext.course_id ||
            this.coursewhitelist.indexOf(lmscontext.course_id) === -1)
        ) {
          return res.status(400).send({
            status: 400,
            error: 'course ' + lmscontext.course_id + ' not on whitelist'
          })
        }

        if (!lmscontext.deploy_id || !lmscontext.resource_id || !lmscontext.iss)
          return res
            .status(400)
            .send({ status: 400, error: 'lti mandatory fields missing' })
        // console.log("lmscontext", lmscontext);
        const lectureinfo = {
          coursetitle:
            payload['https://purl.imsglobal.org/spec/lti/claim/context']
              .title ||
            payload['https://purl.imsglobal.org/spec/lti/claim/context']
              .label ||
            payload['https://purl.imsglobal.org/spec/lti/claim/resource_link']
              .title,
          lecturetitle:
            payload['https://purl.imsglobal.org/spec/lti/claim/resource_link']
              .title
        }
        // console.log("lectureinfo", lectureinfo);

        const rolesKey = 'https://purl.imsglobal.org/spec/lti/claim/roles'
        const role = []
        if (
          payload[rolesKey].includes(
            'http://purl.imsglobal.org/vocab/lis/v2/membership#Learner'
          )
        )
          role.push('audience')

        if (
          payload[rolesKey].includes(
            'http://purl.imsglobal.org/vocab/lis/v2/institution/person#Administrator'
          ) ||
          payload[rolesKey].includes(
            'http://purl.imsglobal.org/vocab/lis/v2/system/person#Administrator'
          )
        ) {
          role.push('administrator')
        }

        if (
          payload[rolesKey].includes(
            'http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor'
          )
        ) {
          if (payload.sub && !this.onlyLearners) {
            role.push('instructor')
          } else role.push('audience') // only audience supported, if anonymous
        }
        // console.log(role);
        // ok we have everything, but now we have to bind it to fails structures
        // we to identify lecture and context, which can be course or the lecture
        // and the user !!
        const failsuser = await this.identifyCreateUser(userinfo)
        // console.log('failsuser', failsuser)
        const courseinfo = { lms: lmscontext, linfo: lectureinfo }
        if (role.includes('instructor') && !role.includes('administrator')) {
          courseinfo.owner = failsuser.useruuid // claim ownership
          courseinfo.ownerdisplayname = failsuser.displayname
        }

        const failscourse = await this.identifyCreateLectureAndCourse(
          courseinfo
        ) // TODO
        if (!failscourse)
          return res
            .status(400)
            .send({ status: 400, error: 'resource can not be identified' })
        // console.log('failscourse', failscourse)

        const token = {
          course: { lectureuuid: failscourse.lectureuuid },
          user: failsuser,
          role: role,
          context: 'lti',
          appversion: failscourse.appversion,
          features: failscourse.features,
          maxrenew: 5
        } // five times 5 minutes should be enough
        const jwttoken = await this.signJwt(token)

        return res.redirect(
          this.basefailsurl[failscourse.appversion] + '/' + '?token=' + jwttoken
        )
      }

      // console.log("decoded token",decodedToken.payload);
    } else
      return res.status(400).send({
        status: 400,
        error: 'Bad Request',
        details: { message: 'no id_token' }
      })
  }

  async identifyCreateUser(userinfo) {
    const userscol = this.mongo.collection('users')

    const orquery = []
    if (userinfo.lmssub) orquery.push({ 'lms.sub': userinfo.lmssub })
    if (userinfo.lmsusername)
      orquery.push({ 'lms.username': userinfo.lmsusername })
    if (userinfo.email) orquery.push({ email: userinfo.email })

    if (orquery.length === 0) return // no user info get out

    const userdoc = await userscol.findOne({ $or: orquery })
    // console.log("user info from db", userdoc);
    let useruuid
    let firstnames = userinfo.firstnames
    let lastname = userinfo.lastname
    let displayname = userinfo.displayname
    let email = userinfo.email

    if (userdoc == null) {
      // deploy data
      const toinsert = {}
      if (!displayname && firstnames && lastname)
        displayname = firstnames + lastname
      if (displayname) toinsert.displayname = displayname
      if (userinfo.firstnames) toinsert.firstnames = userinfo.firstnames
      if (userinfo.lastname) toinsert.lastname = userinfo.lastname
      if (userinfo.email) toinsert.email = userinfo.email
      if (userinfo.lmssub || userinfo.lmsusername) toinsert.lms = {}
      if (userinfo.lmssub) {
        toinsert.lms.sub = userinfo.lmssub
      }
      if (userinfo.lmsusername) {
        toinsert.lms.username = userinfo.lmsusername
      }
      toinsert.lastlogin = new Date()

      useruuid = uuidv4()
      toinsert.uuid = useruuid

      await userscol.insertOne(toinsert)
    } else {
      // check if we want to update
      useruuid = userdoc.uuid
      if (!firstnames) firstnames = userdoc.firstnames
      if (!lastname) lastname = userdoc.lastname
      if (!displayname) displayname = userdoc.displayname
      if (!email) email = userdoc.email

      if (!displayname && firstnames && lastname)
        displayname = firstnames + lastname

      const toupdate = {}
      if (userdoc.displayname !== displayname)
        toupdate.displayname = displayname
      if (userdoc.firstnames !== userinfo.firstnames)
        toupdate.firstnames = userinfo.firstnames
      if (userdoc.lastname !== userinfo.lastname)
        toupdate.lastname = userinfo.lastname
      if (userdoc.email !== userinfo.email) toupdate.email = userinfo.email
      if (
        (userinfo.lmssub || userinfo.lmsusername) &&
        (!userdoc.lms ||
          userdoc.lms.sub !== userinfo.lmssub ||
          userdoc.lms.username !== userinfo.lmsusername)
      ) {
        const updatelms = userdoc.lms
        if (userinfo.lmssub) updatelms.sub = userinfo.lmssub
        if (userinfo.lmsusername) updatelms.username = userinfo.lmsusername
        toupdate.lms = updatelms
      }
      if (Object.keys(toupdate).length > 0) {
        userscol.updateOne(
          { uuid: useruuid },
          { $set: toupdate, $currentDate: { lastlogin: true } }
        )
      } else {
        // console.log("no update",toupdate);
        if (
          !userdoc.lastlogin ||
          (userdoc.lastlogin &&
            moment(userdoc.lastlogin).isBefore(moment().subtract(3, 'days')))
        ) {
          // console.log('renew lastlogin')
          userscol.updateOne(
            { uuid: useruuid },
            { $currentDate: { lastlogin: true } }
          )
        }
      }
    }

    const retobj = { useruuid: useruuid }
    // if (firstnames) retobj.firstnames=firstnames;
    // if (lastname) retobj.lastname=lastname;
    if (displayname) retobj.displayname = displayname
    // if (email) retobj.email=email;
    return retobj
  }

  async identifyCreateLectureAndCourse(args) {
    const lms = args.lms
    const linfo = args.linfo

    const lecturescol = this.mongo.collection('lectures')

    const andquery = []

    if (!lms.iss || !lms.resource_id) {
      console.log('resource can not be identified! abort')
      return null
    }
    andquery.push({ 'lms.iss': lms.iss })
    andquery.push({ 'lms.resource_id': lms.resource_id })

    // TODO add course stuff
    // console.log("andquery", andquery);
    const lecturedoc = await lecturescol.findOne({ $and: andquery })
    // console.log('lecturedoc', lecturedoc)

    let lectureuuid = null

    let title = linfo.lecturetitle
    let coursetitle = linfo.coursetitle

    let appversion = lecturedoc?.appversion || 'stable'
    let features = lecturedoc?.features || []
    if ((lecturedoc == null || !lecturedoc.appversion) && lms.course_id) {
      const lectappdoc = await lecturescol.findOne(
        { $and: [{ 'lms.iss': lms.iss }, { 'lms.course_id': lms.course_id }] },
        { projection: { appversion: 1, features: 1 } }
      )
      if (lectappdoc?.appversion) appversion = lectappdoc.appversion
      if (lectappdoc?.features) features = lectappdoc.features
    }

    if (lecturedoc == null) {
      // deploy data
      const toinsert = {}
      toinsert.lms = {}
      toinsert.lms.iss = lms.iss
      toinsert.lms.resource_id = lms.resource_id
      if (lms.course_id) toinsert.lms.course_id = lms.course_id
      if (lms.platform_id) toinsert.lms.platform_id = lms.platform_id
      if (lms.deploy_id) toinsert.lms.deploy_id = lms.deploy_id
      if (linfo.lecturetitle) toinsert.title = linfo.lecturetitle
      if (linfo.coursetitle) toinsert.coursetitle = linfo.coursetitle
      toinsert.appversion = appversion
      toinsert.features = features
      lectureuuid = uuidv4()
      toinsert.uuid = lectureuuid
      if (args.owner) {
        toinsert.owners = [args.owner]
        if (args.ownerdisplayname)
          toinsert.ownersdisplaynames = [args.ownerdisplayname]
        else toinsert.ownersdisplaynames = ['N.N.']
        toinsert.date = new Date()
        toinsert.lastaccess = new Date()
      }

      await lecturescol.insertOne(toinsert)
    } else {
      if (!title) title = lecturedoc.title
      if (!coursetitle) coursetitle = lecturedoc.coursetitle

      lectureuuid = lecturedoc.uuid
      // check if we want to update
      const toupdate = {}
      if (
        lecturedoc.lms.course_id !== lms.course_id ||
        lecturedoc.lms.platform_id !== lms.platform_id ||
        lecturedoc.lms.deploy_id !== lms.deploy_id
      )
        toupdate.lms = lecturedoc.lms
      if (lecturedoc.lms.course_id !== lms.course_id)
        toupdate.lms.course_id = lms.course_id
      if (lecturedoc.lms.platform_id !== lms.platform_id)
        toupdate.lms.platform_id = lms.platform_id
      if (lecturedoc.lms.deploy_id !== lms.deploy_id)
        toupdate.lms.deploy_id = lms.deploy_id
      if (lecturedoc.title !== linfo.lecturetitle)
        toupdate.title = linfo.lecturetitle
      if (lecturedoc.coursetitle !== linfo.coursetitle)
        toupdate.coursetitle = linfo.coursetitle
      if (!lecturedoc.appversion) lecturedoc.appversion = appversion
      if (!lecturedoc.features) lecturedoc.features = features

      let containsowner = true
      let isowner = false
      if (args.owner) {
        if (lecturedoc.owners)
          containsowner = lecturedoc.owners.includes(args.owner)
        else containsowner = false
        isowner = true
      }

      if (containsowner && !lecturedoc.date) toupdate.date = new Date()
      if (Object.keys(toupdate).length > 0 || !containsowner) {
        const updateops = {}
        if (Object.keys(toupdate).length > 0) updateops.$set = toupdate
        if (!containsowner && isowner) {
          updateops.$addToSet = { owners: args.owner }
          if (args.ownerdisplayname)
            updateops.$push = { ownersdisplaynames: args.ownerdisplayname }
        }
        if (isowner) updateops.$currentDate = { lastaccess: true }
        // console.log("toupdate",updateops);
        lecturescol.updateOne({ uuid: lectureuuid }, updateops)
      } else {
        if (
          !lecturedoc.lastaccess ||
          (lecturedoc.lastaccess &&
            moment(lecturedoc.lastaccess).isBefore(
              moment().subtract(3, 'days')
            ))
        ) {
          if (isowner) {
            lecturescol.updateOne(
              { uuid: lectureuuid },
              { $currentDate: { lastaccess: true } }
            )
          }
        }
      }
    }
    const retobj = { lectureuuid, appversion, features }
    // if (title) retobj.title=title;
    // if (coursetitle) retobj.coursetitle=coursetitle;

    return retobj
  }

  maintenanceExpress() {
    const secretCallback = async (req, { header, payload }) => {
      const keyid = payload.kid
      if (!keyid) throw new Error('no valid kid!')

      const platform = this.lmslist[payload.iss]
      if (!platform) throw new Error('platform not registered/supported')
      let keyinfo
      try {
        keyinfo = await got.get(platform.keyset_url).json()
      } catch (error) {
        console.log('Key info loading problem in maintenance:', error)
        throw new Error('cannot load key info')
      }
      const keys = keyinfo.keys
      if (!keys) throw new Error('Keyset not found')

      const jwk = keys.find((key) => {
        return key.kid === keyid
      })
      if (!jwk) throw new Error('key not found')
      let key
      try {
        key = await Jwk.export({ jwk: jwk })
      } catch (error) {
        console.log('Jwk export: error', error)
        throw new Error('Jwk key export problem')
      }
      return key
    }

    return jwtexpress({
      secret: secretCallback,
      algorithms: ['RS256', 'RS384', 'RS512'],
      requestProperty: 'token'
    })
  }

  async handleGetUser(req, res) {
    const userscol = this.mongo.collection('users')
    const orquery = []

    if (!req.token)
      return res.status(401).send('malformed request: token invalid or missing')
    if (
      req.body.username &&
      req.body.username.match(/^[0-9a-zA-Z._-]+$/) &&
      typeof req.body.username === 'string'
    )
      orquery.push({ 'lms.username': req.body.username })
    if (req.body.email && typeof req.body.email === 'string')
      orquery.push({ email: req.body.email })
    // per spec lmssub is a string, even it is a number for moodle
    if (req.body.lmssub && typeof req.body.lmssub === 'string')
      orquery.push({ 'lms.sub': req.body.lmssub })

    if (orquery.length === 0)
      return res
        .status(401)
        .send('malformed request: missing username or email')
    if (!req.token.iss)
      return res.status(401).send('malformed request: no issuer in token')

    try {
      /* const user = await userscol.findOne({
        $and: [{ $or: orquery }, { 'lms.iss': req.token.iss }]
      }) */ // not this is wrong, we assume that all lms share the usernames and emails with the system
      const user = await userscol.findOne({ $or: orquery })
      if (!user) return res.status(404).send('user not found')
      if (user.uuid) res.status(200).json({ uuid: user.uuid })
      else res.status(404).send('uuid not found')
    } catch (error) {
      console.log('handleGetUser error', error)
      return res.status(500).send('get user error')
    }
  }

  async handleDeleteUser(req, res) {
    if (!validate(req.body.uuid))
      return res.status(401).send('malformed request: missing uuid')
    const useruuid = req.body.uuid
    try {
      const userscol = this.mongo.collection('users')
      const lecturescol = this.mongo.collection('lectures')

      const deleted = await userscol.deleteMany({ uuid: useruuid })

      const mods = await lecturescol.updateMany(
        { owners: useruuid },
        { $pull: { owners: useruuid } }
      )

      res.status(200).json({
        deletedusers: deleted.deletedCount,
        modifieddocs: mods.modifiedCount
      })
    } catch (error) {
      console.log('handleDeleteUser error', error)
      return res.status(500).send('delete user error')
    }
  }

  async handleDeleteCourse(req, res) {
    if (!req.token)
      return res.status(401).send('malformed request: token invalid or missing')
    if (!req.token.iss)
      return res.status(401).send('malformed request: missing iss')
    if (!req.body.courseid)
      return res.status(401).send('malformed request: missing courseid')
    const courseid = Number(req.body.courseid)
    if (Number.isNaN(courseid))
      return res.status(401).send('malformed request: courseid not a number')
    try {
      const lecturescol = this.mongo.collection('lectures')
      const mods = await lecturescol.updateMany(
        { 'lms.iss': req.token.iss, 'lms.course_id': courseid.toString() },
        { $rename: { 'lms.resource_id': 'lms.resource_id_deleted' } }
      )
      res.status(200).json({
        modifieddocs: mods.modifiedCount
      })
    } catch (error) {
      console.log('handleDeleteCourse error', error)
      return res.status(500).send('delete course error')
    }
  }

  async handleDeleteResource(req, res) {
    if (!req.token)
      return res.status(401).send('malformed request: token invalid or missing')
    if (!req.token.iss)
      return res.status(401).send('malformed request: missing issuer')
    if (!req.body.courseid)
      return res.status(401).send('malformed request: missing courseid')
    if (!req.body.resourceid)
      return res.status(401).send('malformed request: missing resourceid')
    const courseid = Number(req.body.courseid)
    if (Number.isNaN(courseid))
      return res.status(401).send('malformed request: courseid not a number')
    const resourceid = Number(req.body.resourceid)
    if (Number.isNaN(resourceid))
      return res.status(401).send('malformed request: resourceid not a number')
    try {
      const lecturescol = this.mongo.collection('lectures')
      const mods = await lecturescol.updateMany(
        {
          'lms.iss': req.token.iss,
          'lms.course_id': courseid.toString(),
          'lms.resource_id': resourceid.toString()
        },
        { $rename: { 'lms.resource_id': 'lms.resource_id_deleted' } }
      )
      res.status(200).json({
        modifieddocs: mods.modifiedCount
      })
    } catch (error) {
      console.log('handleDeleteResource error', error)
      return res.status(500).send('delete resource error')
    }
  }
}
