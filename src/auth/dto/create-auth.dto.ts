import { IsNotEmpty, IsNumber, IsString } from "class-validator";

export class CreateAuthDto {

  @IsNotEmpty()
  // @IsNumber()
  userId: string | number;

  @IsNotEmpty()
  @IsString()
  username: string;
  
  @IsNotEmpty()
  @IsString()
  password: string;
}
