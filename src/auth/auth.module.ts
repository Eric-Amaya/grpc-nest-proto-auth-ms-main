import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthController } from './auth.controller';
import { Auth } from './auth.entity';
import { AuthService } from './service/auth.service';
import { JwtService } from './service/jwt.service';
import { JwtStrategy } from './strategy/jwt.strategy';
import * as dotenv from 'dotenv';
import { EmailService } from './extra/send_email';

dotenv.config();

@Module({
  imports: [
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: '1d' },
    }),
    TypeOrmModule.forFeature([Auth]),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtService, JwtStrategy, EmailService],
  exports: [EmailService]
})
export class AuthModule {}
