import {ITokenStore} from './ITokenStore';
import {IAccessToken} from './IAccessToken';
import * as fs from 'fs';

export class LocalTokenStore implements ITokenStore {
    private storeFile: string;

    constructor(storeFileName: string) {
        this.storeFile = storeFileName;
    }

    public async getStoredToken(): Promise<IAccessToken | null> {
        return new Promise<IAccessToken | null>((resolve, reject) => {
            fs.exists(this.storeFile, (exists) => {
                if (!exists) {
                    resolve(null);
                    return;
                }
                
                fs.readFile(this.storeFile, (error, contents) => {
                    if (error) {
                        reject(error);
                    }
                    
                    try {
                        const token = JSON.parse(contents.toString());
                        if (!this.isAccessToken(token)) {
                            reject('file did not contain access token');
                        } else {
                            resolve(token);
                        }
                    }
                    catch (e) {
                        reject(e);
                    }
                });
            })
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

            fs.writeFile(this.storeFile, JSON.stringify(token), err => {
                if (err) {
                    reject(err);
                } else {
                    resolve();
                }
            });
        });
    }
}

export default LocalTokenStore;