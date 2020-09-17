import * as express from 'express';
import * as passport from 'passport';
export declare type VersionOptions = 'CAS1.0' | 'CAS2.0' | 'CAS3.0';
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
declare type VerifyUser = object | false;
declare type VerifyInfo = {
    message?: string;
} | string;
export declare type VerifyUserInfo = {
    user: VerifyUser;
    info?: VerifyInfo;
};
export declare type VerifyCallback = (err: any, user?: VerifyUser, info?: VerifyInfo) => void;
export declare type VerifyFunction = (profile: string | Profile, done: VerifyCallback) => void;
export declare type VerifyFunctionWithRequest = (req: express.Request, profile: string | Profile, done: VerifyCallback) => void;
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
    private _passReqToCallback;
    constructor(options: StrategyOptions<false>, verify: VerifyFunction);
    constructor(options: StrategyOptions<true>, verify: VerifyFunctionWithRequest);
    private verify;
    private validateCAS1;
    private validateSAML;
    private validateCAS23;
    private service;
    authenticate(req: express.Request, options?: AuthenticateOptions): void;
}
export {};
