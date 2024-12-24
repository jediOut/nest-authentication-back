import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { PrismaService } from 'src/prisma/prisma.service';

import { encrypt } from 'src/libs/bcrypt';
import { compare } from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private prismaServive: PrismaService,
    private jwtService: JwtService,
  ) {}

  async signUp(email: string, password: string) {
    try {
      const userFound = await this.prismaServive.user.findUnique({
        where: {
          email,
        },
      });
      if (userFound)
        throw new BadRequestException(
          `El usuario registrado con el email ${userFound.email} ya esta registrado porfavor use un email con el cual no se haya registrado`,
        );

      const hashedPassword = await encrypt(password);

      const user = await this.prismaServive.user.create({
        data: {
          email,
          password: hashedPassword,
        },
      });

      const { password: _, ...userWithoutPassword } = user;
      const payload = {
        userWithoutPassword,
      };

      const acces_token = await this.jwtService.signAsync(payload);

      return { acces_token };
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      throw new Error(error);
    }
  }

  async login(email: string, password: string) {
    try {
      const user = await this.prismaServive.user.findUnique({
        where: {
          email,
        },
      });

      if (!user) throw new BadRequestException('Email o contraseña invalidos');

      const isPasswordMatch = await compare(password, user.password);

      if (!isPasswordMatch)
        throw new BadRequestException('Email o contraseña invalidos');

      const { password: _, ...userWithoutPassword } = user;

      const payload = {
        userWithoutPassword,
      };

      const acces_token = await this.jwtService.signAsync(payload);

      return { acces_token };
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      throw new InternalServerErrorException('Error al hacer el login');
    }
  }
 
  async getUsers() {
    return await this.prismaServive.user.findMany();
  }

  // findOne(id: number) {
  //   return `This action returns a #${id} auth`;
  // }

  // update(id: number, updateAuthDto: UpdateAuthDto) {
  //   return `This action updates a #${id} auth`;
  // }

  // remove(id: number) {
  //   return `This action removes a #${id} auth`;
  // }
}
