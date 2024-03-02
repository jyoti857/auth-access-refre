import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { jwtConstants } from './constants';
import { PassportModule } from '@nestjs/passport';
import { AtStrategy, RtStrategy } from './strategies';
// const passportModule = PassportModule.register({ defaultStrategy: 'jwt' })
@Module({
  imports: [
    JwtModule.register({}),
    // passportModule
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    AtStrategy,
    RtStrategy
  ],
  exports: [AuthService, 
    // passportModule
  ]
})
export class AuthModule {}
