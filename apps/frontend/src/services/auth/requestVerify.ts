import apiClient from "../apiClient";

export interface RequestVerifyPayload {
    email: string;
    captchaToken: string;
}

export interface RequestVerifyResponse {
    status: boolean;
    message: string;
}

// Request Email Verification
export const requestVerify = async (
    data: RequestVerifyPayload
): Promise<RequestVerifyResponse> => {
    const response = await apiClient.post<RequestVerifyResponse>("/api/auth/request-verify", data);
    return response.data;
};
