/**
 * Apereo CAS Protocol Client (https://apereo.github.io/cas/6.1.x/protocol/CAS-Protocol.html)
 */
import * as url from 'url';

import * as axios from 'axios';
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
    agentOptions?: any;
}

export interface AuthenticateOptions extends passport.AuthenticateOptions {
    loginParams?: { [key: string]: string | undefined };
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

    private _client: axios.AxiosInstance;
    private _verify: VerifyCallback;
    private _validate: (req: express.Request, body: string, verified: DoneCallback) => void;
    private _validateUri: string;
    private _passReqToCallback: boolean;

    constructor(options: StrategyOptions, verify: VerifyCallback) {
        super();

        this.name = 'cas';
        this.version = options.version || 'CAS1.0';
        this.ssoBase = options.ssoBaseURL;
        this.serverBaseURL = options.serverBaseURL;
        this.validateURL = options.validateURL;
        this.serviceURL = options.serviceURL;
        this.useSaml = options.useSaml || false;
        new url.URL(this.ssoBase); // validate base URL

        this._verify = verify;
        this._client = axios.default.create(options.agentOptions);
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
            case 'CAS1.0':
                this._validateUri = '/validate';
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
            case 'CAS2.0':
            case 'CAS3.0':
                if (this.useSaml) {
                    this._validateUri = '/samlValidate';
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
                        this._validateUri = '/p3/serviceValidate';
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

    private service(req: express.Request): string {
        const serviceURL = this.serviceURL || req.originalUrl;
        const resolvedURL = new url.URL(serviceURL, this.serverBaseURL);
        resolvedURL.searchParams.delete('ticket');
        return resolvedURL.toString();
    };

    public authenticate(req: express.Request, options?: AuthenticateOptions) {
        options = options || {};

        // CAS Logout flow as described in
        // https://wiki.jasig.org/display/CAS/Proposal%3A+Front-Channel+Single+Sign-Out var relayState = req.query.RelayState;
        const relayState = req.query.RelayState;
        if (relayState) {
            // logout locally
            req.logout();
            const redirectURL = new url.URL('/logout', this.ssoBase)
            redirectURL.searchParams.append('_eventId', 'next');
            redirectURL.searchParams.append('RelayState', relayState);
            this.redirect(redirectURL.toString());
            return;
        }

        const service = this.service(req);

        const ticket = req.query.ticket;
        if (!ticket) {
            const redirectURL = new url.URL(this.ssoBase, '/login');

            redirectURL.searchParams.append('service', service);
            // copy loginParams in login query
            const loginParams = options.loginParams;
            if (loginParams) {
                for (const loginParamKey in loginParams ) {
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

        const _handleResponse = (response: axios.AxiosResponse<string>) => {
            this._validate(req, response.data, verified);
            return;
        };

        if (this.useSaml) {
            const soapEnvelope = `<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/><SOAP-ENV:Body><samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1" MinorVersion="1" RequestID="${uuidv4()}" IssueInstant="${new Date().toISOString()}"><samlp:AssertionArtifact>${ticket}</samlp:AssertionArtifact></samlp:Request></SOAP-ENV:Body></SOAP-ENV:Envelope>`;

            this._client.post<string>(new url.URL(_validateUri, this.ssoBase).toString(), soapEnvelope, {
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
            .then(_handleResponse).catch((e: any) => {
                this.fail(String(e));
                return;
            });
        } else {
            this._client.get<string>(new url.URL(_validateUri, this.ssoBase).toString(), {
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
            .then(_handleResponse).catch((e: any) => {
                this.fail(String(e));
                return;
            });
        }
    };
}
