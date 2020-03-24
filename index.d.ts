import * as express from 'express';
import * as passport from 'passport';
export declare type VersionOptions = 'CAS1.0' | 'CAS2.0' | 'CAS3.0';
export interface StrategyOptions {
    version?: VersionOptions;
    casBaseURL: string;
    serviceBaseURL: string;
    serviceURL?: string;
    validateURL?: string;
    useSaml?: boolean;
    passReqToCallback?: boolean;
    agentOptions?: any;
}
export interface AuthenticateOptions extends passport.AuthenticateOptions {
    loginParams?: {
        [key: string]: string | undefined;
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
    casBaseURL: string;
    serviceBaseURL: string;
    validateURL?: string;
    serviceURL?: string;
    useSaml: boolean;
    private _client;
    private _verify;
    private _validate;
    private _validateUri;
    private _passReqToCallback;
    constructor(options: StrategyOptions, verify: VerifyCallback);
    private service;
    authenticate(req: express.Request, options?: AuthenticateOptions): void;
}
