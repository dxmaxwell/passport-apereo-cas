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

export interface StrategyOptions<REQ extends boolean = boolean> {
    version?: VersionOptions;
    casBaseURL: string;
    serviceBaseURL: string;
    serviceURL?: string;
    validateURL?: string;
    useSaml?: boolean;
    passReqToCallback?: REQ;
    agentOptions?: any;
}

export interface AuthenticateOptions extends passport.AuthenticateOptions {
    loginParams?: { [key: string]: string | undefined };
}

export interface Profile {
    user: string;
    attributes?: { [key: string]: any };
}

type DoneUser = object | false;
type DoneInfo = { message?: string } | string;
export type DoneUserInfo = { user: DoneUser; info?: DoneInfo };
export type DoneCallback = (err: any, user?: DoneUser, info?: DoneInfo) => void;

export type VerifyCallback = (profile: string | Profile, done: DoneCallback) => void;
export type VerifyCallbackWithRequest =  (req: express.Request, profile: string | Profile, done: DoneCallback) => void;

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

    public casBaseURL: string;
    public serviceBaseURL: string;
    public validateURL?: string;
    public serviceURL?: string;
    public useSaml: boolean;

    private _client: axios.AxiosInstance;
    private _verify: VerifyCallback | VerifyCallbackWithRequest;
    private _validate: (req: express.Request, body: string, verified: DoneCallback) => void;
    private _validateUri: string;
    private _passReqToCallback: boolean;

    constructor(options: StrategyOptions<false>, verify: VerifyCallback);
    constructor(options: StrategyOptions<true>, verify: VerifyCallbackWithRequest);
    constructor(options: StrategyOptions, verify: VerifyCallback | VerifyCallbackWithRequest) {
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
                this._validateUri = './validate';
                this._validate = (req, body, verified) => {
                    const lines = body.split('\n');
                    if (lines.length >= 1) {
                        if (lines[0] === 'no') {
                            verified(new Error('Authentication failed'));
                            return;
                        } else if (lines[0] === 'yes' && lines.length >= 2) {
                            if (this._passReqToCallback) {
                                (this._verify as VerifyCallbackWithRequest)(req, lines[1], verified);
                            } else {
                                (this._verify as VerifyCallback)(lines[1], verified);
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
                    this._validateUri = './samlValidate';
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
                                        (this._verify as VerifyCallbackWithRequest)(req, profile, verified);
                                    } else {
                                        (this._verify as VerifyCallback)(profile, verified);
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
                        this._validateUri = './serviceValidate';
                    } else {
                        this._validateUri = './p3/serviceValidate';
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
                                        (this._verify as VerifyCallbackWithRequest)(req, success, verified);
                                    } else {
                                        (this._verify as VerifyCallback)(success, verified);
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

    private validateCAS(req: express.Request, body: string): Promise<DoneUserInfo> {
        return new Promise<DoneUserInfo>((resolve, reject) => {
            this._validate(req, body, (err: any, user, info) => {
                if (err) {
                    reject(err);
                    return;
                }
                resolve({ user: user || false, info });
            });
        });
    }

    private validateSAML(req: express.Request, body: string): Promise<DoneUserInfo> {
        return this.validateCAS(req, body);
    }

    private service(req: express.Request): string {
        const serviceURL = this.serviceURL || req.originalUrl;
        const resolvedURL = new url.URL(serviceURL, this.serviceBaseURL);
        resolvedURL.searchParams.delete('ticket');
        return resolvedURL.toString();
    };

    public authenticate(req: express.Request, options?: AuthenticateOptions) {
    Promise.resolve().then(async (): Promise<void> => {
        options = options || {};

        // CAS Logout flow as described in
        // https://wiki.jasig.org/display/CAS/Proposal%3A+Front-Channel+Single+Sign-Out var relayState = req.query.RelayState;
        const relayState = req.query.RelayState;
        if (typeof relayState === 'string' && relayState) {
            // logout locally
            req.logout();
            const redirectURL = new url.URL('./logout', this.casBaseURL)
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

        let _validateUri = this.validateURL;

        let userInfo: DoneUserInfo;
        if (this.useSaml) {
            const soapEnvelope = `<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/><SOAP-ENV:Body><samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1" MinorVersion="1" RequestID="${uuidv4()}" IssueInstant="${new Date().toISOString()}"><samlp:AssertionArtifact>${ticket}</samlp:AssertionArtifact></samlp:Request></SOAP-ENV:Body></SOAP-ENV:Envelope>`;
            if (!_validateUri) {
                _validateUri = './samlValidate';
            }
            let response: axios.AxiosResponse<string>;
            try {
            response = await this._client.post<string>(new url.URL(_validateUri, this.casBaseURL).toString(), soapEnvelope, {
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
            } catch (err: unknown) {
                this.fail(String(err), 500);
                return;
            }
            try {
                userInfo = await this.validateSAML(req, response.data);
            } catch (err: unknown) {
                this.error(err);
                return;
            }
        } else {
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
            let response: axios.AxiosResponse<string>;
            try {
            response = await this._client.get<string>(new url.URL(_validateUri, this.casBaseURL).toString(), {
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
            } catch (err: unknown) {
                this.fail(String(err), 500);
                return;
            }
            try {
                userInfo = await this.validateCAS(req, response.data);
            } catch (err: unknown) {
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
            } else if (!info || !info.message) {
                this.fail();
            } else {
                this.fail(info.message);
            }
            return;
        }
        this.success(userInfo.user, userInfo.info as (object | undefined));
    })
    .catch((err: any) => {
        this.error(err);
        return;
    });
    };
}
