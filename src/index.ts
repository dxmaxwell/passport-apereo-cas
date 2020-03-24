/**
 * Apereo CAS Protocol Client (https://apereo.github.io/cas/6.1.x/protocol/CAS-Protocol.html)
 */
import * as url from 'url';
import * as http from 'http';
import * as https from 'https';
import * as util from 'util';

import * as express from 'express';
import * as passport from 'passport';
import { v4 as uuidv4 } from 'uuid';
import * as xml2js from 'xml2js';

export type VersionOptions = 'CAS1.0' | 'CAS2.0' | 'CAS3.0';

export interface StrategyOptions {
    version?: VersionOptions;
    ssoBaseURL: string;
    serverBaseURL: string;
    serviceURL?: string;
    validateURL?: string;
    useSaml?: boolean;
    passReqToCallback?: boolean;
}

export interface AuthenticateOptions extends passport.AuthenticateOptions {
    loginParams?: { [key: string]: string | string[] };
}

export interface Profile {
    user: string;
    attributes?: { [key: string]: any };
}

export type DoneCallback = (err: any, user?: any, info?: any) => void;

export interface VerifyCallback {
    (profile: string | Profile, done: DoneCallback): void;
    (req: express.Request, profile: string | Profile, done: DoneCallback): void;
}

// See specification: https://apereo.github.io/cas/6.1.x/protocol/CAS-Protocol-Specification.html#42-samlvalidate-cas-30
interface SAMLValidateResult {
    envelope: {
        body: {
            response: {
                status: {
                    statuscode: {
                        $: {
                            Value: string;
                        }
                    }
                },
                assertion: {
                    attributestatement: {
                        attribute: {
                            $: {
                                AttributeName: string
                            },
                            attributevalue: object;
                        }[]
                    },
                    authenticationstatement: {
                        subject: {
                            nameidentifier: string
                        }
                    }
                }
            }
        }
    }
}

// See specification: https://apereo.github.io/cas/6.1.x/protocol/CAS-Protocol-Specification.html#28-p3servicevalidate-cas-30
interface CASValidateResult {
    serviceresponse: {
        authenticationsuccess: {
            user: string;
            proxygrantingticket: string;
        },            
        authenticationfailure?: {
            $: {
                code: string;
            },
        }
    }
}

export class Strategy extends passport.Strategy {

    public name: string;

    public version: VersionOptions;

    public ssoBase: string;
    public serverBaseURL: string;
    public validateURL?: string;
    public serviceURL?: string;
    public useSaml: boolean;
    public parsed: url.UrlObject;
    public client: any;

    private _verify: VerifyCallback;
    private _validate: (req: express.Request, body: string, verified: DoneCallback) => void;
    private _validateUri: string;
    private _passReqToCallback: boolean;

    constructor(options: StrategyOptions, verify: VerifyCallback) {
        super();

        this.version = options.version || "CAS1.0";
        this.ssoBase = options.ssoBaseURL;
        this.serverBaseURL = options.serverBaseURL;
        this.validateURL = options.validateURL;
        this.serviceURL = options.serviceURL;
        this.useSaml = options.useSaml || false;
        this.parsed = url.parse(this.ssoBase);
        if (this.parsed.protocol === 'http:') {
            this.client = http;
        } else {
            this.client = https;
        }

        this.name = 'cas';
        this._verify = verify;
        this._passReqToCallback = options.passReqToCallback || false;

        var xmlParseOpts: xml2js.Options = {
            'trim': true,
            'normalize': true,
            'explicitArray': false,
            'tagNameProcessors': [
                xml2js.processors.normalize,
                xml2js.processors.stripPrefix
            ]
        };

        var self = this;
        switch (this.version) {
            case "CAS1.0":
                this._validateUri = "/validate";
                this._validate = (req, body, verified) => {
                    var lines = body.split('\n');
                    if (lines.length >= 1) {
                        if (lines[0] === 'no') {
                            return verified(new Error('Authentication failed'));
                        } else if (lines[0] === 'yes' && lines.length >= 2) {
                            if (self._passReqToCallback) {
                                self._verify(req, lines[1], verified);
                            } else {
                                self._verify(lines[1], verified);
                            }
                            return;
                        }
                    }
                    return verified(new Error('The response from the server was bad'));
                };
                break;
            case "CAS2.0":
            case "CAS3.0":
                if (this.useSaml) {
                    this._validateUri = "/samlValidate";
                    this._validate = (req, body, verified) => {
                        xml2js.parseString(body, xmlParseOpts, (err, result: SAMLValidateResult) => {
                            if (err) {
                                return verified(new Error('The response from the server was bad'));
                            }
                            try {
                                var response = result.envelope.body.response;
                                var success = response.status.statuscode['$'].Value.match(/Success$/);
                                if (success) {
                                    var attributes: { [key: string]: object } = {};
                                    if (Array.isArray(response.assertion.attributestatement.attribute)) {
                                        for (const attribute of response.assertion.attributestatement.attribute) {
                                            attributes[attribute['$'].AttributeName.toLowerCase()] = attribute.attributevalue;
                                        };
                                    }
                                    var profile = {
                                        'user': response.assertion.authenticationstatement.subject.nameidentifier,
                                        'attributes': attributes
                                    };
                                    if (self._passReqToCallback) {
                                        self._verify(req, profile, verified);
                                    } else {
                                        self._verify(profile, verified);
                                    }
                                    return;
                                }
                                return verified(new Error('Authentication failed'));
                            } catch (e) {
                                return verified(new Error('Authentication failed'));
                            }
                        });
                    };
                } else {
                    if (this.version === 'CAS2.0') {
                        this._validateUri = '/serviceValidate';
                    } else {
                        this._validateUri = "/p3/serviceValidate";
                    }
                    this._validate = (req, body, verified) => {
                        xml2js.parseString(body, xmlParseOpts, (err, result: CASValidateResult) => {
                            if (err) {
                                return verified(new Error('The response from the server was bad'));
                            }
                            try {
                                if (result.serviceresponse.authenticationfailure) {
                                    return verified(new Error('Authentication failed ' + result.serviceresponse.authenticationfailure.$.code));
                                }
                                var success = result.serviceresponse.authenticationsuccess;
                                if (success) {
                                    if (self._passReqToCallback) {
                                        self._verify(req, success, verified);
                                    } else {
                                        self._verify(success, verified);
                                    }
                                    return;
                                }
                                return verified(new Error('Authentication failed'));

                            } catch (e) {
                                return verified(new Error('Authentication failed'));
                            }
                        });
                    };
                }
                break;
            default:
                throw new Error('unsupported version ' + this.version);
        }
    }

    private service(req: express.Request) {
        var serviceURL = this.serviceURL || req.originalUrl;
        var resolvedURL = url.resolve(this.serverBaseURL, serviceURL);
        var parsedURL = url.parse(resolvedURL, true);
        delete parsedURL.query.ticket;
        delete parsedURL.search;
        return url.format(parsedURL);
    };

    public authenticate(req: express.Request, options?: AuthenticateOptions) {
        options = options || {};

        // CAS Logout flow as described in
        // https://wiki.jasig.org/display/CAS/Proposal%3A+Front-Channel+Single+Sign-Out var relayState = req.query.RelayState;
        var relayState = req.query.RelayState;
        if (relayState) {
            // logout locally
            req.logout();
            return this.redirect(this.ssoBase + '/logout?_eventId=next&RelayState=' +
                relayState);
        }

        var service = this.service(req);

        var ticket = req.query.ticket;
        if (!ticket) {
            var redirectURL = url.parse(this.ssoBase + '/login', true);

            redirectURL.query.service = service;
            // copy loginParams in login query
            for (var property in options.loginParams ) {
                var loginParam = options.loginParams[property];
                if (loginParam) {
                    redirectURL.query[property] = loginParam;
                }
            }
            return this.redirect(url.format(redirectURL));
        }

        var self = this;
        var verified = (err: any, user?: object, info?: object) => {
            if (err) {
                return self.error(err);
            }
            if (!user) {
                return self.fail(String(info));
            }
            self.success(user, info);
        };
        var _validateUri = this.validateURL || this._validateUri;

        var _handleResponse = (response: http.IncomingMessage) => {
            response.setEncoding('utf8');
            var body = '';
            response.on('data', (chunk) => {
                return body += chunk;
            });
            return response.on('end', () => {
                return self._validate(req, body, verified);
            });
        };

        if (this.useSaml) {
            var requestId = uuidv4();
            var issueInstant = new Date().toISOString();
            var soapEnvelope = util.format('<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/><SOAP-ENV:Body><samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1" MinorVersion="1" RequestID="%s" IssueInstant="%s"><samlp:AssertionArtifact>%s</samlp:AssertionArtifact></samlp:Request></SOAP-ENV:Body></SOAP-ENV:Envelope>', requestId, issueInstant, ticket);
            var request = this.client.request({
                host: this.parsed.hostname,
                port: this.parsed.port,
                method: 'POST',
                path: url.format({
                    pathname: this.parsed.pathname + _validateUri,
                    query: {
                        'TARGET': service
                    }
                })
            }, _handleResponse);

            request.on('error', (e: any) => {
                return self.fail(String(e));
            });
            request.write(soapEnvelope);
            request.end();
        } else {
            var get = this.client.get({
                host: this.parsed.hostname,
                port: this.parsed.port,
                path: url.format({
                    pathname: this.parsed.pathname + _validateUri,
                    query: {
                        ticket: ticket,
                        service: service
                    }
                })
            }, _handleResponse);

            get.on('error', (e: any) => {
                return self.fail(String(e));
            });
        }
    };
}
