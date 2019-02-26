import * as https from 'https';
import * as http from 'http';
import {EventEmitter} from 'events';
import {IAccessToken} from './IAccessToken';
import {ITokenStore} from './ITokenStore';

export interface IShortcodeAuth extends EventEmitter {
    on(event: string, listener: () => void): this;
    on(event: 'authorized', listener: (token: IAccessToken) => void): this;
    on(event: 'declined', listener: () => void): this;
    on(event: 'completed', listener: () => void): this;
    on(event: 'expired', listener: () => void): this;
    on(event: 'code', listener: (code: string) => void): this;
    on(event: 'error', listener: (error: Error) => void): this;
}

export interface IOauthClientInfo {
    client_id: string;
    client_secret?: string;
    scopes: string[];
}

export interface IMixerOAuthClientInfo {
    client_id: string;
    client_secret?: string;
    scope: string;
}

export interface IMixerOAuthTokenGrant {
    grant_type: string;
    client_id: string;
    refresh_token?: string;
    client_secret?: string;
    code?: string;
};

export class ShortcodeAuthClient extends EventEmitter implements IShortcodeAuth {
    public static TokenPreInvalidatePeriod = 1000 * 60 * 30; // 30 minutes
    public static CheckInterval: number = 1000;
    public static MixerUrl: string = 'mixer.com';
    public static BaseApi: string = '/api/v1';
    public static ShortcodeEndpoint: string = ShortcodeAuthClient.BaseApi + '/oauth/shortcode';
    public static TokenEndpoint: string = ShortcodeAuthClient.BaseApi + '/oauth/token';
    public static CurrentUserEndpoint: string = ShortcodeAuthClient.BaseApi + '/users/current';
    public static ShortcodeCheckEndpoint: string = ShortcodeAuthClient.BaseApi + '/oauth/shortcode/check/{handle}';

    public ClientId: string;
    public ClientSecret: string | null;
    public Scopes: string[];

    public ShortCode: string | null = null;
    private ShortCodeHandle: string | null = null;
    private ShortCodeHandleExpiresTime: Date | null = null;
    private ShortCodeCheckInterval: NodeJS.Timer | null = null;

    private inRequest: boolean = false;
    private request: http.ClientRequest;

    private rawResponse: http.IncomingMessage;
    private responseStr: string = '';

    private tokenStore: ITokenStore | null;

    constructor(clientInfo: IOauthClientInfo, tokenStore?: ITokenStore) {
        super();

        this.ClientId = clientInfo.client_id;
        this.ClientSecret =
            (typeof clientInfo.client_secret !== 'undefined') ? 
                clientInfo.client_secret : null;
        this.Scopes = clientInfo.scopes;
        this.tokenStore = tokenStore || null;
    }

    public doAuth() {
        if (this.inRequest) {
            throw 'A request has already been started in this client!';
        }

        if (this.ClientId === null || typeof this.ClientId !== 'string' || this.ClientId.length < 1) {
            throw 'Invalid client id';
        }

        if (this.ClientSecret !== null && (typeof this.ClientSecret !== 'string' || this.ClientSecret.length < 1)) {
            throw 'Invalid client secret';
        }

        if (this.Scopes.length === 0) {
            throw 'Client must request at least one scope';
        }

        this.doAuthInternal();
    }

    private async doAuthInternal() {
        this.inRequest = true;
        if (this.tokenStore) {
            try {
                const token = this.validateToken(await this.tokenStore.getStoredToken());
                if (null === token || typeof token.access_token !== 'string' || typeof token.refresh_token !== 'string') {
                    this.startShortcodeAuth();
                    return;
                }

                const tokenValid = !this.tokenExpired(token) && await this.tryToken(token);
                if (tokenValid) {
                    console.log('Token valid');
                    await this.authorized(token);
                } else {
                    console.log('Token invalid');
                    const newToken = await this.getOAuthToken(null, token);
                    await this.authorized(newToken);
                }
            } catch (e) {
                console.log('Validation error', e);
                this.startShortcodeAuth();
            }
        } else {
            console.log('No store');
            this.startShortcodeAuth();
        }
    }

    private validateToken(token: IAccessToken): IAccessToken {
        if (typeof token.expires_at === 'string') {
            token.expires_at = new Date(token.expires_at);
        }

        return token;
    }

    private tokenExpired(token: IAccessToken): boolean {
        return token.expires_at.getTime() < (Date.now() - ShortcodeAuthClient.TokenPreInvalidatePeriod);
    }

    private async tryToken(token: IAccessToken) {
        return new Promise((resolve) => { // This function always resolves - returns null on error
            https.get({
                hostname: ShortcodeAuthClient.MixerUrl,
                path: ShortcodeAuthClient.CurrentUserEndpoint,
                headers: {
                    'Authorization': `${token.token_type} ${token.access_token}`
                }
            }, (response) => {
                let data = '';
                response.on('data', chunk => {
                    data += chunk;
                });

                response.on('end', () => {
                    try {
                        if (response.statusCode === 200) {
                            resolve(true);
                        } else {
                            resolve(false);
                        }
                    } catch (e) {
                        this.error(e);
                    }
                });

                response.on('error', () => resolve(false));
            });
        });
    }

    private error(message: Error | string) {
        this.emit('error', message);
        this.emit('completed');
    }

    private startShortcodeAuth() {
        this.request = https.request({
            hostname: ShortcodeAuthClient.MixerUrl,
            path: ShortcodeAuthClient.ShortcodeEndpoint,
            method: 'POST',
            port: 443
        }, response => this.handleShortcodeResponse(response));

        const data: IMixerOAuthClientInfo = {
            client_id: this.ClientId,
            scope: this.Scopes.join(' ')
        };

        if (this.ClientSecret) {
            data['client_secret'] = this.ClientSecret;
        }

        const dataStr = JSON.stringify(data);
        this.request.setHeader('Content-Length', Buffer.byteLength(dataStr));
        this.request.setHeader('Content-Type', 'application/json');
        this.request.write(dataStr);
        this.request.end();
    }

    private handleShortcodeResponse(response: http.IncomingMessage) {
        this.rawResponse = response;
        response.on('data', d => this.handleShortcodeResponseData(d));
        response.on('end', () => this.handleShortcodeResponseDone());
        response.on('error', e => this.handleResponseError(e));
    }

    private handleShortcodeResponseData(data: string | Buffer) {
        if (typeof data === 'string') {
            this.responseStr += data;
        } else if (data instanceof Buffer) {
            const buf = data as Buffer;
            this.responseStr += buf.toString();
        }
    }

    private handleShortcodeResponseDone() {
        try {
            if (this.rawResponse.statusCode !== 200) {
                console.error(this.responseStr);
                throw new Error(`Received ${this.rawResponse.statusCode} from Mixer`);
            }

            const response = JSON.parse(this.responseStr);
            if (typeof response.code !== 'string') {
                throw "Response code was not string";
            } else if (typeof response.handle !== 'string') {
                throw "Response handle was not string";
            } else if (typeof response.expires_in !== 'number') {
                throw "Response expires_in was not number";
            }

            this.ShortCode = response.code;
            this.ShortCodeHandle = response.handle;
            this.ShortCodeHandleExpiresTime = new Date(new Date().getTime() + 1000 * response.expires_in);
            this.emit('code', this.ShortCode);

            this.startCheckInterval();
        }
        catch (e) {
            this.error(e);
        }
    }

    private handleResponseError(error: Error) {
        this.error(error);
    }

    private startCheckInterval() {
        this.ShortCodeCheckInterval = setTimeout(() => this.checkShortcode(), ShortcodeAuthClient.CheckInterval) as any as NodeJS.Timer;
    }

    private checkShortcode() {
        this.ShortCodeCheckInterval = null;

        https.get({
            hostname: ShortcodeAuthClient.MixerUrl,
            path: ShortcodeAuthClient.ShortcodeCheckEndpoint.replace('{handle}', this.ShortCodeHandle as string),
        }, (response) => {
            let data = '';
            response.on('data', chunk => {
                data += chunk;
            });

            response.on('end', () => {
                try {
                    if (response.statusCode === 204) {
                        this.startCheckInterval();
                    } else if (response.statusCode === 200) {
                        this.redeemAuthCodeForToken(data);
                    } else if (response.statusCode === 403) {
                        this.emit('declined');
                        this.emit('completed');
                    } else if (response.statusCode === 404) {
                        this.emit('expired');
                        this.emit('completed');
                    } else if (response.statusCode === 429) {
                        ShortcodeAuthClient.CheckInterval *= 2;
                        this.startCheckInterval();
                    } else {
                        throw 'An error occured talking to Mixer';
                    }
                } catch (e) {
                    this.error(e);
                }
            });

            response.on('error', e => this.error(e));
        });
    }

    private async redeemAuthCodeForToken(rawData: string) {
        this.ShortCodeCheckInterval = null;

         try {
            const codeObj = JSON.parse(rawData);
            if (typeof codeObj.code !== 'string') {
                throw "Received invalid code from mixer";
            }

            try {
                const token = await this.getOAuthToken(codeObj.code);
                await this.authorized(token);
            } catch (e) {
                this.error(e);
            }
         } catch (e) {
             this.error(e);
         }
    }

    private async getOAuthToken(code: string | null, token?: IAccessToken): Promise<IAccessToken> {
        return new Promise<IAccessToken>((resolve, reject) => {
            var dataObj: IMixerOAuthTokenGrant;
            if (code !== null) {
                dataObj = {
                    grant_type: 'authorization_code',
                    client_id: this.ClientId,
                    code: code
                };
            } else if (token !== undefined && token !== null) {
                dataObj = {
                    grant_type: 'refresh_token',
                    refresh_token: `${token.refresh_token}`,
                    client_id: this.ClientId
                };
            } else {
                return reject("Need either an access code or a refresh token to retrieve a token");
            }

            if (null !== this.ClientSecret) {
                dataObj['client_secret'] = this.ClientSecret;
            }

            this.request = https.request({
                hostname: ShortcodeAuthClient.MixerUrl,
                path: ShortcodeAuthClient.TokenEndpoint,
                method: 'POST',
                port: 443
            }, response => {
                let data = '';
                response.on('data', chunk => {
                    data += chunk;
                });

                response.on('end', () => {
                    try {
                        if (response.statusCode === 200) {
                            const token = JSON.parse(data);
                            if (typeof token.access_token !== 'string') {
                                throw "Access token was not a string";
                            }

                            token.expires_at = new Date(new Date().getTime() + token.expires_in * 1000);

                            resolve(token);
                        } else {
                            throw 'An error occured retrieving the token: ' + data;
                        }
                    } catch (e) {
                        reject(e);
                    }
                });

                response.on('error', e => reject(e));
            });

            const dataStr = JSON.stringify(dataObj);
            this.request.setHeader('Content-Length', Buffer.byteLength(dataStr));
            this.request.setHeader('Content-Type', 'application/json');
            this.request.write(dataStr);
            this.request.end();
        });
    }

    private async authorized(token: IAccessToken) {
        if (this.tokenStore) {
            try {
                await this.tokenStore.storeToken(token);
            } catch (e) {
                this.error(e);
                return;
            }
        }

        this.emit('authorized', token);
        this.emit('completed');
    }
}

export default ShortcodeAuthClient;