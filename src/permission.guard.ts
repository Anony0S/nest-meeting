import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { Observable } from 'rxjs';

@Injectable()
export class PermissionGuard implements CanActivate {
  @Inject(Reflector)
  private reflector: Reflector;

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request: Request = context.switchToHttp().getRequest();
    if (!request.user) return true; // 这里判断有没有登录，没有登陆直接放行，会被登录守卫拦截
    const permissions = request.user.permissions;
    const requiredPermissions = this.reflector.getAllAndOverride(
      'require-permission',
      [context.getClass(), context.getHandler()],
    );
    if (!requiredPermissions) return true;

    requiredPermissions.forEach((item: string) => {
      if (!permissions.find((i) => i.code === item))
        throw new UnauthorizedException('您没有访问该接口的权限');
    });

    return true;
  }
}
