import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { JwtPayload, JwtPayloadWithRt } from "../types";
import {Request} from 'express'
import { ForbiddenException, Injectable } from "@nestjs/common";

@Injectable()
export class RtStrategy extends PassportStrategy(Strategy, 'jwt-refresh'){
  constructor(config: ConfigService){
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.get<string>('RT_SECRET'),
      passReqToCallback: true
    })
  }

  validate(req: Request, payload: JwtPayload): JwtPayloadWithRt {
    const refreshToken = req?.get('authorization')?.replace("Bearer", '').trim()
    console.log("validate refresh token rt strategy -- ", {refreshToken})
    if(!refreshToken) throw new ForbiddenException("Refresh token malformed!")
    return{
      ...payload, 
      refreshToken,
  }
  }
}