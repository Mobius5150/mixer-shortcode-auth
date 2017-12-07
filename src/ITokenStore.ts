import {IAccessToken} from './IAccessToken';

export interface ITokenStore {
    getStoredToken(): Promise<IAccessToken>;
    storeToken(token: IAccessToken): Promise<void>;
}

export default ITokenStore;