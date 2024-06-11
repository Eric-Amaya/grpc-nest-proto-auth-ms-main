import { IsEmail, IsString, MinLength, IsInt } from "class-validator";
import { LoginRequest, RegisterRequest, ValidateRequest, GetUserRequest, RemoveRequest } from "./auth.pb";

export class LoginRequestDto implements LoginRequest {
    @IsEmail()
    public readonly email: string;

    @IsString()
    public readonly password: string;
}

export class RegisterRequestDto implements RegisterRequest {
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