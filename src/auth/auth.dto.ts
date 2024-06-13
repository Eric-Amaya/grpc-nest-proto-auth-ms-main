import { IsEmail, IsString, MinLength, IsInt } from "class-validator";
import { LoginRequest, RegisterRequest, ValidateRequest, GetUserRequest, RemoveRequest, RecoveryRequest, VerifyCodeRequest, ChangePasswordRequest } from "./auth.pb";

export class LoginRequestDto implements LoginRequest {
    @IsEmail()
    public readonly email: string;

    @IsString()
    public readonly password: string;
}

export class RegisterRequestDto implements RegisterRequest {
    @IsString()
    public readonly name: string;

    @IsString()
    public readonly rut: string;
    
    @IsEmail()
    public readonly email: string;

    @IsString()
    @MinLength(8)
    public readonly password: string;
}

export class ValidateRequestDto implements ValidateRequest {
    @IsString()
    public readonly token: string;
}

export class GetUserRequestDto implements GetUserRequest {
    @IsInt()
    public readonly userId: number;
}

export class RemoveRequestDto implements RemoveRequest {
    @IsString()
    public readonly token: string;
}

export class RecoveryRequestDto implements RecoveryRequest {
    @IsEmail()
    public readonly email: string;
}

export class VerifyCodeRequestDto implements VerifyCodeRequest {
    @IsEmail()
    public readonly email: string;

    @IsString()
    public readonly code:string;
} 

export class ChangePasswordRequestDto implements ChangePasswordRequest {
    @IsEmail()
    email: string;

    @IsString()
    code: string;

    @IsString()
    @MinLength(8)
    newPassword: string;

    @IsString()
    @MinLength(8)
    confirmPassword: string;

}