import { Injectable } from "@nestjs/common";
import { JwtService as Jwt } from "@nestjs/jwt";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { Auth } from "../auth.entity";
import * as bcrypt from 'bcryptjs';

@Injectable()
export class JwtService {
    @InjectRepository(Auth)
    private readonly repository: Repository<Auth>;

    private readonly jwt: Jwt;

    constructor(jwt: Jwt) {
        this.jwt = jwt;
    }

    //Decoding the JWT token
    public async decode(token: string): Promise<unknown> {
        return this.jwt.decode(token);
    }

    // Get User by User ID we get from decode()
    public async validateUser(decoded: any): Promise<Auth> {
        return this.repository.findOne(decoded.id);
    }

    // Generate JWT Token
    public async generateToken(auth: Auth): Promise <string> {
        return this.jwt.signAsync( { id: auth.id, email: auth.email, role: auth.role } );
    }

    // Validate User's password
    public isPasswordValid(password: string, userPassword: string): boolean {
        return bcrypt.compareSync(password, userPassword);
    }

    // Encode User's password
    public encodePassword(password: string): string {
        const salt: string = bcrypt.genSaltSync(10);

        return bcrypt.hashSync(password, salt);
    }

    // Validate JWT token, throw forbidden error if JWT token is invalid
    public async verifyToken(token: string): Promise<any> {
        try {
            return this.jwt.verify(token);
        }
        catch (err) {
            throw new Error(err.message);
        }
    }

    // Validate recovey code
    public isCodeValid ( entryCode: string, recoveryCode: string): boolean {
        return bcrypt.compareSync(entryCode,recoveryCode);
    }

}