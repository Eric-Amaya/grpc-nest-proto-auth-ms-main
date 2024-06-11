import { HttpStatus, Inject, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from './jwt.service';
import { RegisterRequestDto, LoginRequestDto, ValidateRequestDto, RemoveRequestDto, RecoveryRequestDto } from '../auth.dto';
import { Auth } from '../auth.entity';
import { GetUserRequest, GetUserResponse, LoginResponse, RecoveryResponse, RegisterResponse, RemoveResponse, ValidateResponse } from '../auth.pb';
import { EmailService } from '../extra/send_email';
import { randomBytes } from 'crypto';

@Injectable()
export class AuthService {
    @InjectRepository(Auth)
    private readonly repository: Repository<Auth>;
    @Inject(EmailService)
    private readonly emailService: EmailService;

    @Inject(JwtService)
    private readonly jwtService: JwtService;

    public async getUser({ userId }: GetUserRequest): Promise<GetUserResponse> {
        const user: Auth = await this.repository.findOne({ where: { id: userId } });
    
        if (!user) {
          return { status: HttpStatus.NOT_FOUND, error: ['User not found'], user: null };
        }
    
        return { status: HttpStatus.OK, error: null, user };
      }

    public async register( { email, password }: RegisterRequestDto): Promise<RegisterResponse> {
        let auth: Auth = await this.repository.findOne({ where: { email }});

        if(auth) {
            return { status: HttpStatus.CONFLICT, error: ['Email already exits'] };
        }

        auth = new Auth();

        auth.email = email;
        auth.password = this.jwtService.encodePassword(password);

        await this.repository.save(auth);

        return { status: HttpStatus.CREATED, error: null }; 
    }

    public async login({ email, password }: LoginRequestDto): Promise<LoginResponse> {
        const auth: Auth = await this.repository.findOne({ where: { email }});

        if(!auth) {
            return { status: HttpStatus.NOT_FOUND, error: ['Email not found'], token: null };
        }

        const isPasswordValid: boolean = this.jwtService.isPasswordValid(password, auth.password);

        if(!isPasswordValid) {
            return { status: HttpStatus.NOT_FOUND, error: ['Invalid password'], token: null };
        }

        const token: string = await this.jwtService.generateToken(auth);

        return { token, status: HttpStatus.OK, error: null };
    }

    public async validate( {token}: ValidateRequestDto): Promise<ValidateResponse> {
        const decoded: Auth = await this.jwtService.verifyToken(token);

        if(!decoded) {
            return { status: HttpStatus.FORBIDDEN, error: ['Invalid token'], userId: null, role: null };
        }

        const auth: Auth = await this.jwtService.validateUser(decoded);

        if(!auth) {
            return { status: HttpStatus.CONFLICT, error: ['User not found'], userId: null, role: null };
        }

        return { status: HttpStatus.OK, error: null, userId: decoded.id, role: decoded.role };
    }

    public async remove({ token }: RemoveRequestDto): Promise<RemoveResponse> {
        const decoded: Auth = await this.jwtService.verifyToken(token);
    
        if (!decoded) {
          return { status: HttpStatus.FORBIDDEN, error: ['Invalid token'] };
        }
    
        const auth: Auth = await this.repository.findOne({ where: { id: decoded.id } });
    
        if (!auth) {
          return { status: HttpStatus.NOT_FOUND, error: ['User not found'] };
        }
    
        await this.repository.remove(auth);
    
        return { status: HttpStatus.OK, error: null };
      }

    public async recovery ({ email }: RecoveryRequestDto) : Promise <RecoveryResponse>{
        const user: Auth = await this.repository.findOne({ where: { email } });

        if(!user) {
            return { status: HttpStatus.NOT_FOUND, error: ['Email not found']};
        }

        const code_recovery = this.generatedPassword(10);
        const crypt_code = this.jwtService.encodePassword(code_recovery);
        const to = email;
        const subject = "Password recovery";
        const text = `Here you have your code to recovery your password:\n${code_recovery}`
        await this.emailService.sendEmail(to,subject,text); 

        user.recoveryCode = crypt_code;

        await this.repository.save(user);

        return { status: HttpStatus.CREATED, error: null }; 
    }

    private generatedPassword = (length: number): string => { 
        const charset = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const buffer = randomBytes(length);
        let randomCode = '';
    
        for (let i = 0; i < length; i++) {
          const randomIndex = buffer.readUInt8(i) % charset.length;
          randomCode += charset[randomIndex];
        }
    
        return randomCode;
    }
}