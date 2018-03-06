import {ITokenStore} from './ITokenStore';
import {IAccessToken} from './IAccessToken';

export class CookieTokenStore implements ITokenStore {
    private cookieName: string;

    constructor(cookieName: string) {
        this.cookieName = cookieName;
    }

    public async getStoredToken(): Promise<IAccessToken | null> {
        return new Promise<IAccessToken | null>((resolve, reject) => {
            const cookie = this.getCookie(this.cookieName, null);
            if (null === cookie) {
                resolve(null);
                return;
            }

            try {
                const token = JSON.parse(cookie.toString());
                if (!this.isAccessToken(token)) {
                    reject('cookie did not contain access token');
                } else {
                    resolve(token);
                }
            } catch (e) {
                reject(e);
            }
        });
    }

    private isAccessToken(token: any): boolean {
        return ('access_token' in token) &&
                ('token_type' in token) &&
                ('expires_in' in token) &&
                ('refresh_token' in token);
    }

    public async storeToken(token: IAccessToken): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            if (!this.isAccessToken(token)) {
                reject('Refusing to store something that is not an IAccessToken');
                return;
            }

            let expires: Date = token.expires_at;
            if (!expires) {
                if (token.expires_in) {
                    expires = new Date();
                    expires.setTime(expires.getTime() + 1000*token.expires_in);
                } else {
                    reject('token must have an expiry time');
                    return;
                }
            } else if (!(expires instanceof Date)) {
                expires = new Date(expires);
            }

            this.setCookie(this.cookieName, JSON.stringify(token), expires);
            resolve();
        });
    }

    private setCookie(name: string, value: string, expiryDate: Date) {
        document.cookie = name + "=" + value + ";expires=" + expiryDate.toUTCString() + ";path=/";
    }

    private getCookie<T>(name: string, defaultValue: T): T | string {
        name = name + "=";
        const cookies = decodeURIComponent(document.cookie).split(';');
        for(var i = 0; i < cookies.length; i++) {
            var cookieName = cookies[i].trimLeft();
            if (cookieName.indexOf(name) === 0) {
                return cookieName.substring(name.length, cookieName.length);
            }
        }
        return defaultValue;
    }
}

export default CookieTokenStore;