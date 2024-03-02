import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { JwtService } from "@nestjs/jwt";
import { Request } from "express";
import { jwtConstants } from "src/auth/constants";
import { IS_PUBLIC_KEY } from "src/common/decorators";

@Injectable()
export class AuthGuard implements CanActivate{
  constructor(private jwtService: JwtService, private reflector: Reflector){}
  async canActivate(context: ExecutionContext): Promise<boolean>{

    // check first if the route is public 
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass()
    ]);
    if(isPublic) return true;
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    if(!token) throw new UnauthorizedException();
    try{
      const payload = await this.jwtService.verifyAsync(token, {
        secret: jwtConstants.secret
      })
      console.log("payload verifysync ", {payload})
      request['user'] = payload;
    }catch{
      throw new UnauthorizedException();
    }
    return true; //await Promise.resolve(true);
  }
  extractTokenFromHeader(req: Request): string | undefined {
    const [type, token] = req.headers.authorization?.split(' ') ?? []
    return type === 'Bearer' ? token : undefined
  }

}