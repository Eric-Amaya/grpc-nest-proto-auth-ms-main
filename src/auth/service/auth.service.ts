import { HttpStatus, Inject, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from './jwt.service';
import { RegisterRequestDto, LoginRequestDto, ValidateRequestDto, RemoveRequestDto, RecoveryRequestDto, VerifyCodeRequestDto, ChangePasswordRequestDto } from '../auth.dto';
import { Auth } from '../auth.entity';
import { ChangePasswordResponse, GetUserRequest, GetUserResponse, LoginResponse, RecoveryResponse, RegisterResponse, RemoveResponse, ValidateResponse, VerifyCodeResponse } from '../auth.pb';
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

    public async register( { name, rut, email, password }: RegisterRequestDto): Promise<RegisterResponse> {
        let auth: Auth = await this.repository.findOne({ where: { email }});

        if(auth) {
            return { status: HttpStatus.CONFLICT, error: ['Email already exits'] };
        }

        auth = new Auth();

        auth.name = name;
        auth.rut = rut;
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
        const subject = "Recuperación de contraseña";
        const htmlContent = `
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Recuperación de Contraseña</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        color: #333;
                    }
                    .container {
                        width: 100%;
                        max-width: 600px;
                        margin: 0 auto;
                        padding: 20px;
                        border: 1px solid #ddd;
                        border-radius: 5px;
                        background-color: #f9f9f9;
                    }
                    .header {
                        text-align: center;
                        padding-bottom: 20px;
                    }
                    .code {
                        font-size: 24px;
                        font-weight: bold;
                        color: #d9534f;
                        text-align: center;
                        margin: 20px 0;
                    }
                    .footer {
                        text-align: center;
                        margin-top: 20px;
                        font-size: 12px;
                        color: #777;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Recuperación de Contraseña</h1>
                    </div>
                    <p>Hola,</p>
                    <p>Has solicitado recuperar tu contraseña. Aquí tienes tu código de recuperación:</p>
                    <div class="code">${code_recovery}</div>
                    <p>Si no has solicitado la recuperación de tu contraseña, por favor ignora este correo.</p>
                    <br>
                    <p>Atentamente,</p>
                    <p>Equipo de RESTOCK</p>
                    <div class="footer">
                        <p>Este es un correo automático, por favor no respondas a este mensaje.</p>
                    </div>
                </div>
            </body>
        `
        await this.emailService.sendEmail(to, subject, htmlContent);

        user.recoveryCode = crypt_code;

        await this.repository.save(user);

        return { status: HttpStatus.CREATED, error: null }; 
    }

    public async verifyCode ({ email, code }: VerifyCodeRequestDto) : Promise <VerifyCodeResponse>{
       
        const user: Auth = await this.repository.findOne({ where: {email} })

        if(!user) {
            return { status: HttpStatus.NOT_FOUND, error: ['Email not found']};
        }

        const verifyCode = await this.jwtService.isCodeValid(code,user.recoveryCode);
        if (!verifyCode) {
            return { status: HttpStatus.NOT_FOUND, error: ['Invalid recovery code']}
        }

        return {status: HttpStatus.OK, error: null}
    }

    public async changePassword ({ email, code, newPassword, confirmPassword}: ChangePasswordRequestDto): Promise <ChangePasswordResponse> {
        
        const user: Auth = await this.repository.findOne({ where: {email} });

        if(!user) {
            return { status: HttpStatus.NOT_FOUND, error: ['Email not found']};
        }

        if (!code || !(newPassword === confirmPassword)) {
            return { status: HttpStatus.NOT_FOUND, error: ['Password do not match']};
        }

        user.password = await this.jwtService.encodePassword(newPassword);
        user.recoveryCode = null;
        await this.repository.save(user);

        return {status: HttpStatus.OK, error: null}
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