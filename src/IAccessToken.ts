export interface IAccessToken {
    access_token: string;
    token_type: string;
    expires_in: number;
    expires_at: Date;
    refresh_token: string;
}

export default IAccessToken;