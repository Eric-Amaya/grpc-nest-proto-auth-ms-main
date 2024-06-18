import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from '../auth.controller';
import { AuthService } from '../service/auth.service';
import { 
    RegisterRequestDto,LoginRequestDto,ValidateRequestDto,RemoveRequestDto,RecoveryRequestDto,VerifyCodeRequestDto,ChangePasswordRequestDto 
} from '../auth.dto';
import { 
    RegisterResponse, LoginResponse, ValidateResponse, GetUserRequest, 
    GetUserResponse, RemoveResponse, RecoveryResponse, VerifyCodeResponse, ChangePasswordResponse 
} from '../auth.pb';

describe('AuthController', () => {
    let authController: AuthController;
    let authService: AuthService;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [AuthController],
            providers: [
                {
                    provide: AuthService,
                    useValue: {
                        getUser: jest.fn(),
                        register: jest.fn(),
                        login: jest.fn(),
                        validate: jest.fn(),
                        remove: jest.fn(),
                        recovery: jest.fn(),
                        verifyCode: jest.fn(),
                        changePassword: jest.fn(),
                    },
                },
            ],
        }).compile();

        authController = module.get<AuthController>(AuthController);
        authService = module.get<AuthService>(AuthService);
    });

    test('should be defined', () => {
        expect(authController).toBeDefined();
    });

    test('should call getUser method', async () => {
        const payload: GetUserRequest = { userId: 1 };
        const expectedResult: GetUserResponse = { user: { id: 1, email: 'test@test.com', role: 'admin', name: 'test' }, status: 200, error: null };

        jest.spyOn(authService, 'getUser').mockResolvedValue(expectedResult);

        expect(await authController.getUser(payload)).toBe(expectedResult);
    });

    test('should call register method', async () => {
        const payload: RegisterRequestDto = { name: 'test' ,rut: '123456-9', email: 'test@example.com', password: 'password'};
        const expectedResult: RegisterResponse = { status: 201, error: null };

        jest.spyOn(authService, 'register').mockResolvedValue(expectedResult);

        expect(await authController.register(payload)).toBe(expectedResult);
    });

    test('should call login method', async () => {
        const payload: LoginRequestDto = { email: 'test@example.com', password: 'password' };
        const expectedResult: LoginResponse = { status:200, error:null, token: 'testtoken' };

        jest.spyOn(authService, 'login').mockResolvedValue(expectedResult);

        expect(await authController.login(payload)).toBe(expectedResult);
    });

    test('should call validate method', async () => {
        const payload: ValidateRequestDto = { token: 'testtoken' };
        const expectedResult: ValidateResponse = { status: 200, error: null, userId: 1, role: 'admin' };

        jest.spyOn(authService, 'validate').mockResolvedValue(expectedResult);

        expect(await authController.validate(payload)).toBe(expectedResult);
    });

    test('should call remove method', async () => {
        const payload: RemoveRequestDto = { token: 'testtoken' };
        const expectedResult: RemoveResponse = { status: 200, error: null};

        jest.spyOn(authService, 'remove').mockResolvedValue(expectedResult);

        expect(await authController.remove(payload)).toBe(expectedResult);
    });

    test('should call recovery method', async () => {
        const payload: RecoveryRequestDto = { email: 'test@example.com' };
        const expectedResult: RecoveryResponse = { status: 200, error: null};

        jest.spyOn(authService, 'recovery').mockResolvedValue(expectedResult);

        expect(await authController.recovery(payload)).toBe(expectedResult);
    });

    test('should call verifyCode method', async () => {
        const payload: VerifyCodeRequestDto = { email:'test@test.com',code: '123456' };
        const expectedResult: VerifyCodeResponse = { status: 200, error: null};

        jest.spyOn(authService, 'verifyCode').mockResolvedValue(expectedResult);

        expect(await authController.verifyCode(payload)).toBe(expectedResult);
    });

    test('should call changePassword method', async () => {
        const payload: ChangePasswordRequestDto = { email: 'test@test.com', code:'12345', newPassword: 'newPassword', confirmPassword: 'newpassword' };
        const expectedResult: ChangePasswordResponse = { status: 200, error: null};

        jest.spyOn(authService, 'changePassword').mockResolvedValue(expectedResult);

        expect(await authController.changePassword(payload)).toBe(expectedResult);
    });
});
