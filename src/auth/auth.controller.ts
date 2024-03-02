import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, HttpStatus, HttpCode, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { Tokens } from './types';
import { GetCurrentUser, GetCurrentUsername, Public } from 'src/common/decorators';
import { AuthGuard } from '@nestjs/passport';
import { AtGuard, RtGuard } from 'src/common/guards';
import {Request} from 'express'

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // @Post()
  // create(@Body() createAuthDto: CreateAuthDto) {
  //   return this.authService.create(createAuthDto);
  // }

  // @Get()
  // findAll() {
  //   return this.authService.findAll();
  // }

  // @Get(':username')
  // findOne(@Param('username') username: string) {
  //   return this.authService.findOne(username);
  // }

  // @Patch(':id')
  // update(@Param('id') id: string, @Body() updateAuthDto: UpdateAuthDto) {
  //   return this.authService.update(+id, updateAuthDto);
  // }

  // @Delete(':id')
  // remove(@Param('id') id: string) {
  //   return this.authService.remove(+id);
  // }


  // just for at and rt things 
  @Public()
  @Post('/local/signup')
  signupLocal(@Body() dto: CreateAuthDto): Promise<Tokens>{
    return this.authService.signupLocal(dto);
  }


  @Public()
  // @UseGuards(AtGuard)
  // @UseGuards(AuthGuard('jwt'))
  @Post('local/singin')
  signinLocal(@Body() dto: CreateAuthDto): Promise<Tokens>{
    return this.authService.singinLocal(dto);
  }

  // @Public()
  // @UseGuards(AtGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(@GetCurrentUsername() username: string): Promise<boolean>{
    console.log("user id logout1 AtGuard ", username)
    return this.authService.logout(username)
  }

  // @UseGuards(AuthGuard('jwt'))
  // @Post('logout')
  // logout(@Req() req: Request){
  //   const user = req?.user
  //   console.log("logout controller user ", {user})
  //   return this.authService.logout(user['username'])
  // }

  @Public()
  @UseGuards(RtGuard)
  // @UseGuards(AuthGuard('jwt-refresh'))
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refreshTokens(
    @GetCurrentUsername() username: string, 
    @GetCurrentUser('refreshToken') refreshToken: string
  ){
    return this.authService.refreshTokens(username, refreshToken)
  }
}
