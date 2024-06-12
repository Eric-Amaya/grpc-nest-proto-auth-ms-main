// Code generated by protoc-gen-ts_proto. DO NOT EDIT.
// versions:
//   protoc-gen-ts_proto  v1.176.1
//   protoc               v5.27.0
// source: auth.proto

/* eslint-disable */
import { GrpcMethod, GrpcStreamMethod } from "@nestjs/microservices";
import { Observable } from "rxjs";

export const protobufPackage = "auth";

export interface RegisterRequest {
  email: string;
  password: string;
}

export interface RegisterResponse {
  status: number;
  error: string[];
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  status: number;
  error: string[];
  token: string;
}

export interface ValidateRequest {
  token: string;
}

export interface ValidateResponse {
  status: number;
  error: string[];
  userId: number;
  role: string;
}

export interface EditRequest {
  token: string;
  email: string;
  password: string;
}

export interface EditResponse {
  status: number;
  error: string[];
}

export interface RemoveRequest {
  token: string;
}

export interface RemoveResponse {
  status: number;
  error: string[];
}

export interface GetUserRequest {
  userId: number;
}

export interface GetUserResponse {
  status: number;
  error: string[];
  user: User | undefined;
}

export interface User {
  id: number;
  email: string;
  role: string;
}

export interface RecoveryRequest {
  email: string;
}

export interface RecoveryResponse {
  status: number;
  error: string[];
}

export interface VerifyCodeRequest {
  email: string;
  code: string;
}

export interface VerifyCodeResponse {
  status: number;
  error: string[];
}

export interface ChangePasswordRequest {
  email: string;
  code: string;
  newPassword: string;
  confirmPassword: string;
}

export interface ChangePasswordResponse {
  status: number;
  error: string[];
}

export const AUTH_PACKAGE_NAME = "auth";

export interface AuthServiceClient {
  register(request: RegisterRequest): Observable<RegisterResponse>;

  login(request: LoginRequest): Observable<LoginResponse>;

  validate(request: ValidateRequest): Observable<ValidateResponse>;

  edit(request: EditRequest): Observable<EditResponse>;

  remove(request: RemoveRequest): Observable<RemoveResponse>;

  getUser(request: GetUserRequest): Observable<GetUserResponse>;

  recovery(request: RecoveryRequest): Observable<RecoveryResponse>;

  changePassword(request: ChangePasswordRequest): Observable<ChangePasswordResponse>;

  verifyCode(request: VerifyCodeRequest): Observable<VerifyCodeResponse>;
}

export interface AuthServiceController {
  register(request: RegisterRequest): Promise<RegisterResponse> | Observable<RegisterResponse> | RegisterResponse;

  login(request: LoginRequest): Promise<LoginResponse> | Observable<LoginResponse> | LoginResponse;

  validate(request: ValidateRequest): Promise<ValidateResponse> | Observable<ValidateResponse> | ValidateResponse;

  edit(request: EditRequest): Promise<EditResponse> | Observable<EditResponse> | EditResponse;

  remove(request: RemoveRequest): Promise<RemoveResponse> | Observable<RemoveResponse> | RemoveResponse;

  getUser(request: GetUserRequest): Promise<GetUserResponse> | Observable<GetUserResponse> | GetUserResponse;

  recovery(request: RecoveryRequest): Promise<RecoveryResponse> | Observable<RecoveryResponse> | RecoveryResponse;

  changePassword(
    request: ChangePasswordRequest,
  ): Promise<ChangePasswordResponse> | Observable<ChangePasswordResponse> | ChangePasswordResponse;

  verifyCode(
    request: VerifyCodeRequest,
  ): Promise<VerifyCodeResponse> | Observable<VerifyCodeResponse> | VerifyCodeResponse;
}

export function AuthServiceControllerMethods() {
  return function (constructor: Function) {
    const grpcMethods: string[] = [
      "register",
      "login",
      "validate",
      "edit",
      "remove",
      "getUser",
      "recovery",
      "changePassword",
      "verifyCode",
    ];
    for (const method of grpcMethods) {
      const descriptor: any = Reflect.getOwnPropertyDescriptor(constructor.prototype, method);
      GrpcMethod("AuthService", method)(constructor.prototype[method], method, descriptor);
    }
    const grpcStreamMethods: string[] = [];
    for (const method of grpcStreamMethods) {
      const descriptor: any = Reflect.getOwnPropertyDescriptor(constructor.prototype, method);
      GrpcStreamMethod("AuthService", method)(constructor.prototype[method], method, descriptor);
    }
  };
}

export const AUTH_SERVICE_NAME = "AuthService";
