import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from '../auth/auth.module';
import { ConfigModule } from '@nestjs/config';
import { PrismaModule } from 'src/prisma/prisma.module';
import { APP_GUARD } from '@nestjs/core';
import { AtGuard } from 'src/common/guards';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from 'src/auth/auth.service';

@Module({
  imports: [
    ConfigModule.forRoot({isGlobal: true}),
    AuthModule,
    PrismaModule,
    // PassportModule
  ],
  // controllers: [AppController],
  providers: [
    AppService,
    // AuthService
    {
      provide: APP_GUARD,
      useClass: AtGuard
    }
  ],
})
export class AppModule {}
