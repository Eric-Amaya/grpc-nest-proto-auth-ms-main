import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { JwtService } from '../service/jwt.service';
import { Auth } from '../auth.entity';
import { Repository } from 'typeorm';
import { JwtService as NestJwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';

const mockAuthRepository = () => ({
    findOne: jest.fn(),
});

const mockJwtService = {
    decode: jest.fn(),
    signAsync: jest.fn(),
    verify: jest.fn(),
};

describe('JwtService', () => {
    let jwtService: JwtService;
    let authRepository: Repository<Auth>;
    let nestJwtService: NestJwtService;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                JwtService,
                { provide: getRepositoryToken(Auth), useValue: mockAuthRepository() },
                { provide: NestJwtService, useValue: mockJwtService },
            ],
        }).compile();

        jwtService = module.get<JwtService>(JwtService);
        authRepository = module.get<Repository<Auth>>(getRepositoryToken(Auth));
        nestJwtService = module.get<NestJwtService>(NestJwtService);
    });

    test('should be defined', () => {
        expect(jwtService).toBeDefined();
    });

    describe('decode', () => {
        test('should decode a token', async () => {
            const decodedValue = { id: 1 };
            (nestJwtService.decode as jest.Mock).mockReturnValue(decodedValue);

            const result = await jwtService.decode('token');
            expect(result).toEqual(decodedValue);
        });
    });

    describe('validateUser', () => {
        test('should return a user by decoded id', async () => {
            const user = { id: 1, email: 'test@example.com' };
            (authRepository.findOne as jest.Mock).mockResolvedValue(user);

            const result = await jwtService.validateUser({ id: 1 });
            expect(result).toEqual(user);
        });
    });

    describe('generateToken', () => {
        test('should generate a token', async () => {
            const user = { id: 1, email: 'test@example.com', role: 'user' };
            (nestJwtService.signAsync as jest.Mock).mockResolvedValue('token');

            const result = await jwtService.generateToken(user as Auth);
            expect(result).toBe('token');
        });
    });

    describe('isPasswordValid', () => {
        test('should return true if password is valid', () => {
            const password = 'password';
            const userPassword = bcrypt.hashSync(password, 10);

            const result = jwtService.isPasswordValid(password, userPassword);
            expect(result).toBe(true);
        });

        test('should return false if password is invalid', () => {
            const password = 'password';
            const userPassword = bcrypt.hashSync('differentPassword', 10);

            const result = jwtService.isPasswordValid(password, userPassword);
            expect(result).toBe(false);
        });
    });

    describe('encodePassword', () => {
        test('should encode a password', () => {
            const password = 'password';

            const result = jwtService.encodePassword(password);
            expect(result).not.toBe(password);
            expect(bcrypt.compareSync(password, result)).toBe(true);
        });
    });

    describe('verifyToken', () => {
        test('should verify a token', async () => {
            const decodedValue = { id: 1 };
            (nestJwtService.verify as jest.Mock).mockReturnValue(decodedValue);

            const result = await jwtService.verifyToken('token');
            expect(result).toEqual(decodedValue);
        });

        test('should throw an error if token is invalid', async () => {
            (nestJwtService.verify as jest.Mock).mockImplementation(() => {
                throw new Error('Invalid token');
            });

            await expect(jwtService.verifyToken('invalidToken')).rejects.toThrow('Invalid token');
        });
    });

    describe('isCodeValid', () => {
        test('should return true if recovery code is valid', () => {
            const entryCode = 'code';
            const recoveryCode = bcrypt.hashSync(entryCode, 10);

            const result = jwtService.isCodeValid(entryCode, recoveryCode);
            expect(result).toBe(true);
        });

        test('should return false if recovery code is invalid', () => {
            const entryCode = 'code';
            const recoveryCode = bcrypt.hashSync('differentCode', 10);

            const result = jwtService.isCodeValid(entryCode, recoveryCode);
            expect(result).toBe(false);
        });
    });
});
