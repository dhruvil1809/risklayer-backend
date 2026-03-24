import apiClient from "../apiClient";

export interface AuthVerifyPayload {
    email: string;
    otp: string;
}

export interface AuthVerifyResponse {
    status: boolean;
    message: string;
    data?: {
        token: string;
    };
}

// Auth Verify
export const authVerify = async (
    data: AuthVerifyPayload
): Promise<AuthVerifyResponse> => {
    const response = await apiClient.post<AuthVerifyResponse>("/api/auth/verify", data);
    return response.data;
};
