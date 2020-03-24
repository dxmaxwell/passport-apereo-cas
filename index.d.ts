/// <reference types="node" />
/**
 * Apereo CAS Protocol Client (https://apereo.github.io/cas/6.1.x/protocol/CAS-Protocol.html)
 */
import * as url from 'url';
import * as express from 'express';
import * as passport from 'passport';
export declare type VersionOptions = 'CAS1.0' | 'CAS2.0' | 'CAS3.0';
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
    loginParams?: {
        [key: string]: string | string[];
    };
}
export interface Profile {
    user: string;
    attributes?: {
        [key: string]: any;
    };
}
export declare type DoneCallback = (err: any, user?: any, info?: any) => void;
export interface VerifyCallback {
    (profile: string | Profile, done: DoneCallback): void;
    (req: express.Request, profile: string | Profile, done: DoneCallback): void;
}
export declare class Strategy extends passport.Strategy {
    name: string;
    version: VersionOptions;
    ssoBase: string;
    serverBaseURL: string;
    validateURL?: string;
    serviceURL?: string;
    useSaml: boolean;
    parsed: url.UrlObject;
    private _client;
    private _verify;
    private _validate;
    private _validateUri;
    private _passReqToCallback;
    constructor(options: StrategyOptions, verify: VerifyCallback);
    private service;
    authenticate(req: express.Request, options?: AuthenticateOptions): void;
}
