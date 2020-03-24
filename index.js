"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
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
        this.version = options.version || "CAS1.0";
        this.ssoBase = options.ssoBaseURL;
        this.serverBaseURL = options.serverBaseURL;
        this.validateURL = options.validateURL;
        this.serviceURL = options.serviceURL;
        this.useSaml = options.useSaml || false;
        this.parsed = url.parse(this.ssoBase);
        this._client = axios.default.create(options.agentOptions);
        this.name = 'cas';
        this._verify = verify;
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
            case "CAS1.0":
                this._validateUri = "/validate";
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
            case "CAS2.0":
            case "CAS3.0":
                if (this.useSaml) {
                    this._validateUri = "/samlValidate";
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
                        this._validateUri = '/serviceValidate';
                    }
                    else {
                        this._validateUri = "/p3/serviceValidate";
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
    service(req) {
        const serviceURL = this.serviceURL || req.originalUrl;
        const resolvedURL = url.resolve(this.serverBaseURL, serviceURL);
        const parsedURL = url.parse(resolvedURL, true);
        delete parsedURL.query.ticket;
        delete parsedURL.search;
        return url.format(parsedURL);
    }
    ;
    authenticate(req, options) {
        options = options || {};
        // CAS Logout flow as described in
        // https://wiki.jasig.org/display/CAS/Proposal%3A+Front-Channel+Single+Sign-Out var relayState = req.query.RelayState;
        const relayState = req.query.RelayState;
        if (relayState) {
            // logout locally
            req.logout();
            return this.redirect(`${this.ssoBase}/logout?_eventId=next&RelayState=${relayState}`);
        }
        const service = this.service(req);
        const ticket = req.query.ticket;
        if (!ticket) {
            const redirectURL = url.parse(`${this.ssoBase}/login`, true);
            redirectURL.query.service = service;
            // copy loginParams in login query
            for (const property in options.loginParams) {
                const loginParam = options.loginParams[property];
                if (loginParam) {
                    redirectURL.query[property] = loginParam;
                }
            }
            this.redirect(url.format(redirectURL));
            return;
        }
        const verified = (err, user, info) => {
            if (err) {
                return this.error(err);
            }
            if (!user) {
                return this.fail(String(info));
            }
            this.success(user, info);
        };
        const _validateUri = this.validateURL || this._validateUri;
        const _handleResponse = (response) => {
            this._validate(req, response.data, verified);
            return;
        };
        if (this.useSaml) {
            const soapEnvelope = `<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/><SOAP-ENV:Body><samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1" MinorVersion="1" RequestID="${uuid_1.v4()}" IssueInstant="${new Date().toISOString()}"><samlp:AssertionArtifact>${ticket}</samlp:AssertionArtifact></samlp:Request></SOAP-ENV:Body></SOAP-ENV:Envelope>`;
            this._client.post(this.ssoBase + _validateUri, soapEnvelope, {
                params: {
                    TARGET: service,
                },
                headers: {
                    'Content-Type': 'application/xml',
                    'Accept': 'application/xml',
                    'Accept-Charset': 'utf-8',
                },
                responseType: 'text',
            })
                .then(_handleResponse).catch((e) => {
                this.fail(String(e));
                return;
            });
        }
        else {
            this._client.get(this.ssoBase + _validateUri, {
                params: {
                    ticket: ticket,
                    service: service,
                },
                headers: {
                    'Accept': 'application/xml',
                    'Accept-Charset': 'utf-8',
                },
                responseType: 'text',
            })
                .then(_handleResponse).catch((e) => {
                this.fail(String(e));
                return;
            });
        }
    }
    ;
}
exports.Strategy = Strategy;
