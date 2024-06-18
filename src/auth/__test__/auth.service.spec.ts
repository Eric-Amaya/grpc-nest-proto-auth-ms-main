import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { AuthService } from '../service/auth.service';
import { Auth } from '../auth.entity';
import { JwtService } from '../service/jwt.service';
import { EmailService } from '../extra/send_email';
import { Repository } from 'typeorm';
import { HttpStatus } from '@nestjs/common';
import {
    RegisterRequestDto, LoginRequestDto, ValidateRequestDto, RemoveRequestDto,
    RecoveryRequestDto, VerifyCodeRequestDto, ChangePasswordRequestDto
} from '../auth.dto';
import { GetUserRequest } from '../auth.pb';

const mockAuthRepository = () => ({
    findOne: jest.fn(),
    save: jest.fn(),
    remove: jest.fn(),
});

const mockJwtService = () => ({
    encodePassword: jest.fn(),
    isPasswordValid: jest.fn(),
    generateToken: jest.fn(),
    verifyToken: jest.fn(),
    validateUser: jest.fn(),
    isCodeValid: jest.fn(),
});

const mockEmailService = () => ({
    sendEmail: jest.fn(),
});

describe('AuthService', () => {
    let authService: AuthService;
    let authRepository;
    let jwtService;
    let emailService;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                AuthService,
                { provide: getRepositoryToken(Auth), useValue: mockAuthRepository() },
                { provide: JwtService, useValue: mockJwtService() },
                { provide: EmailService, useValue: mockEmailService() },
            ],
        }).compile();

        authService = module.get<AuthService>(AuthService);
        authRepository = module.get<Repository<Auth>>(getRepositoryToken(Auth));
        jwtService = module.get<JwtService>(JwtService);
        emailService = module.get<EmailService>(EmailService);
    });

    test('Should be defined', () => {
        expect(authService).toBeDefined();
    });

    describe('getUser', () => {
        test('Should return user if found', async () => {
            const user = { id: 'test', email: 'test@example.com' };
            authRepository.findOne.mockResolvedValue(user);

            const result = await authService.getUser({ userId: 1 } as GetUserRequest);
            expect(result).toEqual({ status: HttpStatus.OK, error: null, user });
        });

        test('Should return error if user not found', async () => {
            authRepository.findOne.mockResolvedValue(null);

            const result = await authService.getUser({ userId: 1 } as GetUserRequest);
            expect(result).toEqual({ status: HttpStatus.NOT_FOUND, error: ['User not found'], user: null });
        });
    });

    describe('register', () => {
        test('Should register a new user', async () => {
            const payload: RegisterRequestDto = { name: 'test', rut: '123', email: 'test@example.com', password: 'password' };
            authRepository.findOne.mockResolvedValue(null);
            jwtService.encodePassword.mockReturnValue('hashedPassword');

            const result = await authService.register(payload);
            expect(result).toEqual({ status: HttpStatus.CREATED, error: null });
            expect(authRepository.save).toHaveBeenCalled();
        });

        test('Should return conflict if email already exists', async () => {
            const payload: RegisterRequestDto = { name: 'test', rut: '123', email: 'test@example.com', password: 'password' };
            authRepository.findOne.mockResolvedValue({ email: 'test@example.com' });

            const result = await authService.register(payload);
            expect(result).toEqual({ status: HttpStatus.CONFLICT, error: ['Email already exits'] });
        });
    });

    describe('login', () => {
        test('Should login user with valid credentials', async () => {
            const payload: LoginRequestDto = { email: 'test@example.com', password: 'password' };
            const user = { email: 'test@example.com', password: 'hashedPassword' };
            authRepository.findOne.mockResolvedValue(user);
            jwtService.isPasswordValid.mockReturnValue(true);
            jwtService.generateToken.mockResolvedValue('token');

            const result = await authService.login(payload);
            expect(result).toEqual({ status: HttpStatus.OK, error: null, token: 'token' });
        });

        test('Should return error if email not found', async () => {
            const payload: LoginRequestDto = { email: 'test@example.com', password: 'password' };
            authRepository.findOne.mockResolvedValue(null);

            const result = await authService.login(payload);
            expect(result).toEqual({ status: HttpStatus.NOT_FOUND, error: ['Email not found'], token: null });
        });

        test('Should return error if password is invalid', async () => {
            const payload: LoginRequestDto = { email: 'test@example.com', password: 'password' };
            const user = { email: 'test@example.com', password: 'hashedPassword' };
            authRepository.findOne.mockResolvedValue(user);
            jwtService.isPasswordValid.mockReturnValue(false);

            const result = await authService.login(payload);
            expect(result).toEqual({ status: HttpStatus.NOT_FOUND, error: ['Invalid password'], token: null });
        });
    });

    describe('validate', () => {
        test('Should validate token', async () => {
            const payload: ValidateRequestDto = { token: 'token' };
            const decoded = { id: 1, role: 'user' };
            jwtService.verifyToken.mockResolvedValue(decoded);
            jwtService.validateUser.mockResolvedValue({ id: 1});

            const result = await authService.validate(payload);
            expect(result).toEqual({ status: HttpStatus.OK, error: null, userId: decoded.id, role: decoded.role });
        });

        test('Should return error if token is invalid', async () => {
            const payload: ValidateRequestDto = { token: 'token' };
            jwtService.verifyToken.mockResolvedValue(null);

            const result = await authService.validate(payload);
            expect(result).toEqual({ status: HttpStatus.FORBIDDEN, error: ['Invalid token'], userId: null, role: null });
        });

        test('Should return error if user not found', async () => {
            const payload: ValidateRequestDto = { token: 'token' };
            const decoded = { id: 'test', role: 'user' };
            jwtService.verifyToken.mockResolvedValue(decoded);
            jwtService.validateUser.mockResolvedValue(null);

            const result = await authService.validate(payload);
            expect(result).toEqual({ status: HttpStatus.CONFLICT, error: ['User not found'], userId: null, role: null });
        });
    });

    describe('remove', () => {
        test('Should remove user', async () => {
            const payload: RemoveRequestDto = { token: 'token' };
            const decoded = { id: 1 };
            const user = { id: 1 };
            jwtService.verifyToken.mockResolvedValue(decoded);
            authRepository.findOne.mockResolvedValue(user);

            const result = await authService.remove(payload);
            expect(result).toEqual({ status: HttpStatus.OK, error: null });
            expect(authRepository.remove).toHaveBeenCalledWith(user);
        });

        test('Should return error if token is invalid', async () => {
            const payload: RemoveRequestDto = { token: 'token' };
            jwtService.verifyToken.mockResolvedValue(null);

            const result = await authService.remove(payload);
            expect(result).toEqual({ status: HttpStatus.FORBIDDEN, error: ['Invalid token'] });
        });

        test('Should return error if user not found', async () => {
            const payload: RemoveRequestDto = { token: 'token' };
            const decoded = { id: 1 };
            jwtService.verifyToken.mockResolvedValue(decoded);
            authRepository.findOne.mockResolvedValue(null);

            const result = await authService.remove(payload);
            expect(result).toEqual({ status: HttpStatus.NOT_FOUND, error: ['User not found'] });
        });
    });

    describe('recovery', () => {
        test('Should send recovery email', async () => {
            const payload: RecoveryRequestDto = { email: 'test@example.com' };
            const user = { id: 1, email: 'test@example.com' };
            authRepository.findOne.mockResolvedValue(user);
            jwtService.encodePassword.mockReturnValue('encodedCode');
            emailService.sendEmail.mockResolvedValue(true);

            const result = await authService.recovery(payload);
            expect(result).toEqual({ status: HttpStatus.CREATED, error: null });
            expect(authRepository.save).toHaveBeenCalledWith({ ...user, recoveryCode: 'encodedCode' });
        });

        test('Should return error if email not found', async () => {
            const payload: RecoveryRequestDto = { email: 'test@example.com' };
            authRepository.findOne.mockResolvedValue(null);

            const result = await authService.recovery(payload);
            expect(result).toEqual({ status: HttpStatus.NOT_FOUND, error: ['Email not found'] });
        });
    });

    describe('verifyCode', () => {
        test('Should verify recovery code', async () => {
            const payload: VerifyCodeRequestDto = { email: 'test@example.com', code: 'code' };
            const user = { email: 'test@example.com', recoveryCode: 'encodedCode' };
            authRepository.findOne.mockResolvedValue(user);
            jwtService.isCodeValid.mockReturnValue(true);

            const result = await authService.verifyCode(payload);
            expect(result).toEqual({ status: HttpStatus.OK, error: null });
        });

        test('Should return error if email not found', async () => {
            const payload: VerifyCodeRequestDto = { email: 'test@example.com', code: 'code' };
            authRepository.findOne.mockResolvedValue(null);

            const result = await authService.verifyCode(payload);
            expect(result).toEqual({ status: HttpStatus.NOT_FOUND, error: ['Email not found'] });
        });

        test('Should return error if code is invalid', async () => {
            const payload: VerifyCodeRequestDto = { email: 'test@example.com', code: 'code' };
            const user = { email: 'test@example.com', recoveryCode: 'encodedCode' };
            authRepository.findOne.mockResolvedValue(user);
            jwtService.isCodeValid.mockReturnValue(false);

            const result = await authService.verifyCode(payload);
            expect(result).toEqual({ status: HttpStatus.NOT_FOUND, error: ['Invalid recovery code'] });
        });
    });

    describe('changePassword', () => {
        test('Should change password', async () => {
            const payload: ChangePasswordRequestDto = {
                email: 'test@example.com',
                code: 'code',
                newPassword: 'newPassword',
                confirmPassword: 'newPassword'
            };
            const user = { email: 'test@example.com', recoveryCode: 'encodedCode' };
            authRepository.findOne.mockResolvedValue(user);
            jwtService.isCodeValid.mockReturnValue(true);
            jwtService.encodePassword.mockReturnValue('newEncodedPassword');

            const result = await authService.changePassword(payload);
            expect(result).toEqual({ status: HttpStatus.OK, error: null });
            expect(authRepository.save).toHaveBeenCalledWith({ ...user, password: 'newEncodedPassword', recoveryCode: null });
        });

        test('Should return error if email not found', async () => {
            const payload: ChangePasswordRequestDto = {
                email: 'test@example.com',
                code: 'code',
                newPassword: 'newPassword',
                confirmPassword: 'newPassword'
            };
            authRepository.findOne.mockResolvedValue(null);

            const result = await authService.changePassword(payload);
            expect(result).toEqual({ status: HttpStatus.NOT_FOUND, error: ['Email not found'] });
        });

        test('Should return error if passwords do not match', async () => {
            const payload: ChangePasswordRequestDto = {
                email: 'test@example.com',
                code: 'code',
                newPassword: 'newPassword',
                confirmPassword: 'differentPassword'
            };
            const user = { email: 'test@example.com', recoveryCode: 'encodedCode' };
            authRepository.findOne.mockResolvedValue(user);

            const result = await authService.changePassword(payload);
            expect(result).toEqual({ status: HttpStatus.NOT_FOUND, error: ['Password do not match'] });
        });
    });
});
