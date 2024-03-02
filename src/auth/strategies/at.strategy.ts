import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { JwtPayload } from "../types";
import { Injectable } from "@nestjs/common";


@Injectable()
export class AtStrategy extends PassportStrategy(Strategy, 'jwt'){
  constructor(config: ConfigService){
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.get<string>('AT_SECRET')
    });
    console.log("this.config.get1 ", config.get('AT_SECRET'), 
    
    ExtractJwt.fromAuthHeaderAsBearerToken())
  }
  validate(payload: JwtPayload){
    console.log("at strategy payload --- ", {payload})
    return payload;
  }
}