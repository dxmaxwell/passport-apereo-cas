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

        const xmlParseOpts: xml2js.Options = {
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
                        } else if (lines[0] === 'yes' && lines.length >= 2) {
                            if (this._passReqToCallback) {
                                this._verify(req, lines[1], verified);
                            } else {
                                this._verify(lines[1], verified);
                            }
                            return;
                        }
                    }
                    verified(new Error('The response from the server was bad'));
                    return
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
                                const response = result.envelope.body.response;
                                const success = response.status.statuscode['$'].Value.match(/Success$/);
                                if (success) {
                                    const attributes: { [key: string]: object } = {};
                                    if (Array.isArray(response.assertion.attributestatement.attribute)) {
                                        for (const attribute of response.assertion.attributestatement.attribute) {
                                            attributes[attribute['$'].AttributeName.toLowerCase()] = attribute.attributevalue;
                                        };
                                    }
                                    const profile = {
                                        'user': response.assertion.authenticationstatement.subject.nameidentifier,
                                        'attributes': attributes
                                    };
                                    if (this._passReqToCallback) {
                                        this._verify(req, profile, verified);
                                    } else {
                                        this._verify(profile, verified);
                                    }
                                    return;
                                }
                                verified(new Error('Authentication failed'));
                                return;
                            } catch (e) {
                                verified(new Error('Authentication failed'));
                                return;
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
                                const success = result.serviceresponse.authenticationsuccess;
                                if (success) {
                                    if (this._passReqToCallback) {
                                        this._verify(req, success, verified);
                                    } else {
                                        this._verify(success, verified);
                                    }
                                    return;
                                }
                                verified(new Error('Authentication failed'));
                                return;

                            } catch (e) {
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

    private service(req: express.Request) {
        const serviceURL = this.serviceURL || req.originalUrl;
        const resolvedURL = url.resolve(this.serverBaseURL, serviceURL);
        const parsedURL = url.parse(resolvedURL, true);
        delete parsedURL.query.ticket;
        delete parsedURL.search;
        return url.format(parsedURL);
    };

    public authenticate(req: express.Request, options?: AuthenticateOptions) {
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
            for (const property in options.loginParams ) {
                const loginParam = options.loginParams[property];
                if (loginParam) {
                    redirectURL.query[property] = loginParam;
                }
            }
            this.redirect(url.format(redirectURL));
            return;
        }

        const verified = (err: any, user?: object, info?: object) => {
            if (err) {
                return this.error(err);
            }
            if (!user) {
                return this.fail(String(info));
            }
            this.success(user, info);
        };
        const _validateUri = this.validateURL || this._validateUri;

        const _handleResponse = (response: http.IncomingMessage) => {
            response.setEncoding('utf8');
            let body = '';
            response.on('data', (chunk) => {
                body += chunk;
                return;
            });
            return response.on('end', () => {
                this._validate(req, body, verified);
                return;
            });
        };

        if (this.useSaml) {
            const requestId = uuidv4();
            const issueInstant = new Date().toISOString();
            const soapEnvelope = util.format('<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/><SOAP-ENV:Body><samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1" MinorVersion="1" RequestID="%s" IssueInstant="%s"><samlp:AssertionArtifact>%s</samlp:AssertionArtifact></samlp:Request></SOAP-ENV:Body></SOAP-ENV:Envelope>', requestId, issueInstant, ticket);
            const request = this.client.request({
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
                this.fail(String(e));
                return;
            });
            request.write(soapEnvelope);
            request.end();
        } else {
            const get = this.client.get({
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
                this.fail(String(e));
                return;
            });
        }
    };
}
