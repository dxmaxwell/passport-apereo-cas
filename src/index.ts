/**
 * Apereo CAS Protocol Client (https://apereo.github.io/cas/6.1.x/protocol/CAS-Protocol.html)
 */
import * as url from 'url';

import { HttpsProxyAgent } from 'https-proxy-agent';

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

type ValidateProfileInfo = { profile: false | string | Profile, info?: string };

type VerifyUser = object | false;
type VerifyInfo = { message?: string } | string;
export type VerifyUserInfo = { user: VerifyUser; info?: VerifyInfo };
export type VerifyCallback = (err: any, user?: VerifyUser, info?: VerifyInfo) => void;

export type VerifyFunction = (profile: string | Profile, done: VerifyCallback) => void;
export type VerifyFunctionWithRequest =  (req: express.Request, profile: string | Profile, done: VerifyCallback) => void;

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
    private _verify: VerifyFunction | VerifyFunctionWithRequest;
    private _passReqToCallback: boolean;

    constructor(options: StrategyOptions<false>, verify: VerifyFunction);
    constructor(options: StrategyOptions<true>, verify: VerifyFunctionWithRequest);
    constructor(options: StrategyOptions, verify: VerifyFunction | VerifyFunctionWithRequest) {
        super();

        this.name = 'cas';
        this.version = options.version || 'CAS1.0';
        this.casBaseURL = new url.URL(options.casBaseURL).toString();
        this.serviceBaseURL = new url.URL(options.serviceBaseURL).toString();
        this.validateURL = options.validateURL;
        this.serviceURL = options.serviceURL;
        this.useSaml = options.useSaml || false;

        this._verify = verify;
        this._passReqToCallback = options.passReqToCallback || false;

        // Work around for the 'borked' Axios HTTPS proxy support!
        // https://stackoverflow.com/questions/43240483/how-to-use-axios-to-make-an-https-call
        const httpsProxy = process.env.https_proxy || process.env.HTTPS_PROXY
                            || process.env.all_proxy || process.env.ALL_PROXY;
        if (this.casBaseURL.startsWith('https:') && httpsProxy) {
            this._client = axios.default.create({
                httpsAgent: new HttpsProxyAgent(httpsProxy),
                proxy: false,
            });
        } else {
            this._client = axios.default.create();
        }

        if (![ 'CAS1.0', 'CAS2.0', 'CAS3.0'].includes(this.version)) {
            throw new Error(`Unsupported CAS protocol version: ${this.version}`);
        }
    }

    private verify(req: express.Request, profile: string | Profile): Promise<VerifyUserInfo> {
        return new Promise<VerifyUserInfo>((resolve, reject) => {
            const verified = (err: any, user?: VerifyUser, info?: VerifyInfo) => {
                if (err) {
                    reject(err);
                    return;
                }
                resolve({ user: user || false, info });
            };
            if (this._passReqToCallback) {
                (this._verify as VerifyFunctionWithRequest)(req, profile, verified);
            } else {
                (this._verify as VerifyFunction)(profile, verified);
            }
        });
    }

    private async validateCAS1(req: express.Request, result: string[]): Promise<ValidateProfileInfo> {
        if (result.length < 2 || result[0] !== 'yes' || result[1] === '') {
            return { profile: false, info: 'Authentication failed' };
        }
        return { profile: result[1] };
    };

    private async validateSAML(req: express.Request, result: SAMLValidateResult): Promise<ValidateProfileInfo> {
        const response = result.envelope.body.response;
        const success = response.status.statuscode['$'].Value.match(/Success$/);
        if (!success) {
            return { profile: false, info: 'Authentication failed' };
        }
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
        return { profile };
    }
 
    private async validateCAS23(req: express.Request, result: CASValidateResult): Promise<ValidateProfileInfo> {
        const failure = result.serviceresponse.authenticationfailure;
        if (failure) {
            const code = failure.$ && failure.$.code;
            return { profile: false, info: `Authentication failed: Reason: ${code || 'UNKNOWN'}` };
        }
        const profile = result.serviceresponse.authenticationsuccess;
        if (!profile) {
            return { profile: false, info: 'Authentication failed: Missing profile' };
        }
        return { profile };
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

            let profileInfo: ValidateProfileInfo;
            if (this.useSaml) {
                const soapEnvelope = `<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/><SOAP-ENV:Body><samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1" MinorVersion="1" RequestID="${uuidv4()}" IssueInstant="${new Date().toISOString()}"><samlp:AssertionArtifact>${ticket}</samlp:AssertionArtifact></samlp:Request></SOAP-ENV:Body></SOAP-ENV:Envelope>`;
                const validateURL = new url.URL(this.validateURL || './samlValidate', this.casBaseURL).toString();
                try {
                    const response = await this._client.post<string>(validateURL, soapEnvelope, {
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
                    const result: SAMLValidateResult = await xml2js.parseStringPromise(response.data, {
                        'trim': true,
                        'normalize': true,
                        'explicitArray': false,
                        'tagNameProcessors': [
                            xml2js.processors.normalize,
                            xml2js.processors.stripPrefix
                        ]
                    });
                    profileInfo = await this.validateSAML(req, result);
                } catch (err: unknown) {
                    this.fail(String(err), 500);
                    return;
                }
            } else {
                let validateURL: string;
                switch (this.version) {
                default:
                case 'CAS1.0':
                    validateURL = new url.URL(this.validateURL || './validate', this.casBaseURL).toString();
                    break;
                case 'CAS2.0':
                    validateURL = new url.URL(this.validateURL || './serviceValidate', this.casBaseURL).toString();
                    break;
                case 'CAS3.0':
                    validateURL = new url.URL(this.validateURL || './p3/serviceValidate', this.casBaseURL).toString();
                    break;
                }
                try {
                    const response = await this._client.get<string>(validateURL, {
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
                    switch (this.version) {
                        default:
                        case 'CAS1.0': {
                            const result = response.data.split('\n').map((s) => s.trim());
                            profileInfo = await this.validateCAS1(req, result);
                            break;
                        }
                        case 'CAS2.0':
                        case 'CAS3.0': {
                            const result: CASValidateResult = await xml2js.parseStringPromise(response.data, {
                                'trim': true,
                                'normalize': true,
                                'explicitArray': false,
                                'tagNameProcessors': [
                                    xml2js.processors.normalize,
                                    xml2js.processors.stripPrefix
                                ]
                            });
                            profileInfo = await this.validateCAS23(req, result);
                            break;
                        }
                    }
                } catch (err: unknown) {
                    this.fail(String(err), 500);
                    return;
                }
            }

            if (profileInfo.profile === false) {
                this.fail(profileInfo.info);
                return;
            }

            let userInfo: VerifyUserInfo;
            try {
                userInfo = await this.verify(req, profileInfo.profile);
            } catch (err: unknown) {
                this.error(err);
                return;
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
