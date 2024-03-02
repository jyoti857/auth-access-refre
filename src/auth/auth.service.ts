import { ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import {JwtService} from '@nestjs/jwt'
import { PrismaService } from 'src/prisma/prisma.service';
import { ConfigService } from '@nestjs/config';
import { JwtPayload, Tokens } from './types';
import * as argon from 'argon2'
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private prisma: PrismaService,
    private config: ConfigService 
  ){}
  private readonly users = [
    {
      userId: 1,
      username: 'john',
      password: 'changeme',
    },
    {
      userId: 2,
      username: 'maria',
      password: 'guess',
    },
  ];
  create(createAuthDto: CreateAuthDto) {
    return 'This action adds a new auth';
  }

  findAll() {
    return `This action returns all auth`;
  }

  findOne(username: string): Promise<CreateAuthDto | undefined> {
    return new Promise((res, rej) => {
      if(username){
        res(this.users.find(user => user.username === username))
      }else rej(new Error("user is not found!"))
    })
  }

  async signIn(username: string, pass: string): Promise<{access_token: string}>{
    const user = this.users.find(user => user.username === username)
    if(user?.password !== pass){
      throw new UnauthorizedException();
    }
    const payload = {sub: user.userId, username: user.username}
    const {password, ...result} = user;
    return {
      access_token: await this.jwtService.signAsync(payload)
    }
  }

  async validateUser(username: string, pass: string): Promise<any>{
    const user = this.users.find(user => user.username === username)
    if(user && user.password === pass){
      const {password, ...rest} = user;
      return Promise.resolve(rest);
    }
    return null;
  }
  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }


  // for AT and RToken implementation
  async signupLocal(dto: CreateAuthDto): Promise<Tokens>{
    const hash = await argon.hash(dto.password);
    const user = await this.prisma.user.create({
      data: {
        username: dto.username,
        password: dto.password,
        hash,
      }
    })
    .catch((err) => {
      if(err instanceof PrismaClientKnownRequestError){
        if(err.code === 'P2002'){
          throw new ForbiddenException("Credentials incorrect!")
        }
        throw err;
      }
    });

    const tokens = await this.getTokens(user && user.id, user && user.username)
    await this.updateRtHash(user && user.username, tokens.refresh_token);
    
    return tokens;
  }

  async singinLocal(dto: CreateAuthDto): Promise<Tokens>{
    const user = await this.prisma.user.findUnique({
      where: {
        username: dto.username,
      },
    });
    if(!user) throw new ForbiddenException('Access Denied!')
    const passwordMatches = await argon.verify(user && user.hash, dto.password);
    if(!passwordMatches) throw new ForbiddenException("Access Denied!");
    
    const tokens = await this.getTokens(user && user.id, user && user.username);
    await this.updateRtHash(user.username, tokens.refresh_token);

    return tokens;
  }

  async logout(username: string): Promise<boolean>{
    console.log("user id -- from logout authservice  ", {username})
    await this.prisma.user.updateMany({
      where: {
        username,
        hashedRt: {
          not: null,
        },
      },
      data: {
        hashedRt: null
      }
    });
    return true;
  }

  async refreshTokens(username: string, rt: string): Promise<Tokens>{
    const user = await this.prisma.user.findUnique({
      where: {
        username
      }
    });
    if(!user || !user.hashedRt) throw new ForbiddenException("Access Denied!")
    const rtMatches = await argon.verify(user.hashedRt, rt);
    if(!rtMatches) throw new ForbiddenException("Access Denied!")
    const tokens = await this.getTokens(user.id, user.username);
    await this.updateRtHash(user.username, tokens.refresh_token);

    return tokens;
  }

  async getTokens(userId: string, username: string): Promise<Tokens>{
    const jwtPayload: JwtPayload = {
      sub: userId,
      username
    }

    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: this.config.get<string>('AT_SECRET'),
        expiresIn: '1d'
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: this.config.get<string>('RT_SECRET'),
        expiresIn: '7d'
      })
    ]);
    return {
      access_token: at,
      refresh_token: rt
    }
  }

  async updateRtHash(username: string, rt: string){
    const hash = await argon.hash(rt);
    await this.prisma.user.update({
      where: {
        username
      },
      data: {
        hashedRt: hash
      }
    })
  }
}
