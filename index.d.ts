declare module "index" {
    export var Strategy: typeof Strategy;
    function Strategy(options: any, verify: any): void;
    class Strategy {
        constructor(options: any, verify: any);
        version: any;
        ssoBase: any;
        serverBaseURL: any;
        validateURL: any;
        serviceURL: any;
        useSaml: any;
        parsed: any;
        client: any;
        name: string;
        _verify: any;
        _passReqToCallback: any;
        _validateUri: string;
        _validate: (req: any, body: any, verified: any) => any;
        service(req: any): any;
        authenticate(req: any, options: any): any;
    }
    export {};
}
