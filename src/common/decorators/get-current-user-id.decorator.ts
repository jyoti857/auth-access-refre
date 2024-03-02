import { createParamDecorator, ExecutionContext } from "@nestjs/common";
import { JwtPayload } from "src/auth/types";


export const GetCurrentUsername = createParamDecorator((_: undefined, context: ExecutionContext): string =>{
  const request = context.switchToHttp().getRequest();
  const user = request.user as JwtPayload;
  console.log("getCurrentUserId &&& == ", {user})
  return user?.username
})