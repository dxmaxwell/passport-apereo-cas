"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Strategy = void 0;
/**
 * Apereo CAS Protocol Client (https://apereo.github.io/cas/6.1.x/protocol/CAS-Protocol.html)
 */
const url = require("url");
const axios = require("axios");
const passport = require("passport");
const uuid_1 = require("uuid");
const xml2js = require("xml2js");
class Strategy extends passport.Strategy {
    constructor(options, verify) {
        super();
        this.name = 'cas';
        this.version = options.version || 'CAS1.0';
        this.casBaseURL = new url.URL(options.casBaseURL).toString();
        this.serviceBaseURL = new url.URL(options.serviceBaseURL).toString();
        this.validateURL = options.validateURL;
        this.serviceURL = options.serviceURL;
        this.useSaml = options.useSaml || false;
        this._verify = verify;
        this._client = axios.default.create(options.agentOptions);
        this._passReqToCallback = options.passReqToCallback || false;
        const xmlParseOpts = {
            'trim': true,
            'normalize': true,
            'explicitArray': false,
            'tagNameProcessors': [
                xml2js.processors.normalize,
                xml2js.processors.stripPrefix
            ]
        };
        switch (this.version) {
            case 'CAS1.0':
                this._validateUri = './validate';
                this._validate = (req, body, verified) => {
                    const lines = body.split('\n');
                    if (lines.length >= 1) {
                        if (lines[0] === 'no') {
                            verified(new Error('Authentication failed'));
                            return;
                        }
                        else if (lines[0] === 'yes' && lines.length >= 2) {
                            if (this._passReqToCallback) {
                                this._verify(req, lines[1], verified);
                            }
                            else {
                                this._verify(lines[1], verified);
                            }
                            return;
                        }
                    }
                    verified(new Error('The response from the server was bad'));
                    return;
                };
                break;
            case 'CAS2.0':
            case 'CAS3.0':
                if (this.useSaml) {
                    this._validateUri = './samlValidate';
                    this._validate = (req, body, verified) => {
                        xml2js.parseString(body, xmlParseOpts, (err, result) => {
                            if (err) {
                                return verified(new Error('The response from the server was bad'));
                            }
                            try {
                                const response = result.envelope.body.response;
                                const success = response.status.statuscode['$'].Value.match(/Success$/);
                                if (success) {
                                    const attributes = {};
                                    if (Array.isArray(response.assertion.attributestatement.attribute)) {
                                        for (const attribute of response.assertion.attributestatement.attribute) {
                                            attributes[attribute['$'].AttributeName.toLowerCase()] = attribute.attributevalue;
                                        }
                                        ;
                                    }
                                    const profile = {
                                        'user': response.assertion.authenticationstatement.subject.nameidentifier,
                                        'attributes': attributes
                                    };
                                    if (this._passReqToCallback) {
                                        this._verify(req, profile, verified);
                                    }
                                    else {
                                        this._verify(profile, verified);
                                    }
                                    return;
                                }
                                verified(new Error('Authentication failed'));
                                return;
                            }
                            catch (e) {
                                verified(new Error('Authentication failed'));
                                return;
                            }
                        });
                    };
                }
                else {
                    if (this.version === 'CAS2.0') {
                        this._validateUri = './serviceValidate';
                    }
                    else {
                        this._validateUri = './p3/serviceValidate';
                    }
                    this._validate = (req, body, verified) => {
                        xml2js.parseString(body, xmlParseOpts, (err, result) => {
                            if (err) {
                                return verified(new Error('The response from the server was bad'));
                            }
                            try {
                                if (result.serviceresponse.authenticationfailure) {
                                    return verified(new Error('Authentication failed ' + result.serviceresponse.authenticationfailure.$.code));
                                }
                                const success = result.serviceresponse.authenticationsuccess;
                                if (success) {
                                    if (this._passReqToCallback) {
                                        this._verify(req, success, verified);
                                    }
                                    else {
                                        this._verify(success, verified);
                                    }
                                    return;
                                }
                                verified(new Error('Authentication failed'));
                                return;
                            }
                            catch (e) {
                                verified(new Error('Authentication failed'));
                                return;
                            }
                        });
                    };
                }
                break;
            default:
                throw new Error('unsupported version ' + this.version);
        }
    }
    validateCAS(req, body) {
        return new Promise((resolve, reject) => {
            this._validate(req, body, (err, user, info) => {
                if (err) {
                    reject(err);
                    return;
                }
                resolve({ user: user || false, info });
            });
        });
    }
    validateSAML(req, body) {
        return this.validateCAS(req, body);
    }
    service(req) {
        const serviceURL = this.serviceURL || req.originalUrl;
        const resolvedURL = new url.URL(serviceURL, this.serviceBaseURL);
        resolvedURL.searchParams.delete('ticket');
        return resolvedURL.toString();
    }
    ;
    authenticate(req, options) {
        Promise.resolve().then(() => __awaiter(this, void 0, void 0, function* () {
            options = options || {};
            // CAS Logout flow as described in
            // https://wiki.jasig.org/display/CAS/Proposal%3A+Front-Channel+Single+Sign-Out var relayState = req.query.RelayState;
            const relayState = req.query.RelayState;
            if (typeof relayState === 'string' && relayState) {
                // logout locally
                req.logout();
                const redirectURL = new url.URL('./logout', this.casBaseURL);
                redirectURL.searchParams.append('_eventId', 'next');
                redirectURL.searchParams.append('RelayState', relayState);
                this.redirect(redirectURL.toString());
                return;
            }
            const service = this.service(req);
            const ticket = req.query.ticket;
            if (!ticket) {
                const redirectURL = new url.URL('./login', this.casBaseURL);
                redirectURL.searchParams.append('service', service);
                // copy loginParams in login query
                const loginParams = options.loginParams;
                if (loginParams) {
                    for (const loginParamKey in loginParams) {
                        if (loginParams.hasOwnProperty(loginParamKey)) {
                            const loginParamValue = loginParams[loginParamKey];
                            if (loginParamValue) {
                                redirectURL.searchParams.append(loginParamValue, loginParamValue);
                            }
                        }
                    }
                }
                this.redirect(redirectURL.toString());
                return;
            }
            let _validateUri = this.validateURL;
            let userInfo;
            if (this.useSaml) {
                const soapEnvelope = `<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/><SOAP-ENV:Body><samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1" MinorVersion="1" RequestID="${uuid_1.v4()}" IssueInstant="${new Date().toISOString()}"><samlp:AssertionArtifact>${ticket}</samlp:AssertionArtifact></samlp:Request></SOAP-ENV:Body></SOAP-ENV:Envelope>`;
                if (!_validateUri) {
                    _validateUri = './samlValidate';
                }
                let response;
                try {
                    response = yield this._client.post(new url.URL(_validateUri, this.casBaseURL).toString(), soapEnvelope, {
                        params: {
                            TARGET: service,
                        },
                        headers: {
                            'Content-Type': 'application/xml',
                            'Accept': 'application/xml',
                            'Accept-Charset': 'utf-8',
                        },
                        responseType: 'text',
                    });
                }
                catch (err) {
                    this.fail(String(err), 500);
                    return;
                }
                try {
                    userInfo = yield this.validateSAML(req, response.data);
                }
                catch (err) {
                    this.error(err);
                    return;
                }
            }
            else {
                if (!_validateUri) {
                    switch (this.version) {
                        default:
                        case 'CAS1.0':
                            _validateUri = './validate';
                            break;
                        case 'CAS2.0':
                            _validateUri = './serviceValidate';
                            break;
                        case 'CAS3.0':
                            _validateUri = './p3/serviceValidate';
                            break;
                    }
                }
                let response;
                try {
                    response = yield this._client.get(new url.URL(_validateUri, this.casBaseURL).toString(), {
                        params: {
                            ticket: ticket,
                            service: service,
                        },
                        headers: {
                            'Accept': 'application/xml',
                            'Accept-Charset': 'utf-8',
                        },
                        responseType: 'text',
                    });
                }
                catch (err) {
                    this.fail(String(err), 500);
                    return;
                }
                try {
                    userInfo = yield this.validateCAS(req, response.data);
                }
                catch (err) {
                    this.error(err);
                    return;
                }
            }
            // Support `info` of type string, even though it is
            // not supported by the passport type definitions.
            // Recommend use of an object like `{ message: 'Failed' }`
            if (!userInfo.user) {
                const info = userInfo.info;
                if (typeof info === 'string') {
                    this.fail(info);
                }
                else if (!info || !info.message) {
                    this.fail();
                }
                else {
                    this.fail(info.message);
                }
                return;
            }
            this.success(userInfo.user, userInfo.info);
        }))
            .catch((err) => {
            this.error(err);
            return;
        });
    }
    ;
}
exports.Strategy = Strategy;
