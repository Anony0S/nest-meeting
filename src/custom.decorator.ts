import {
  ExecutionContext,
  SetMetadata,
  createParamDecorator,
} from '@nestjs/common';
import { Request } from 'express';

/**
 * @description 登录鉴权
 */
export const RequireLogin = () => SetMetadata('require-login', true);

/**
 * @description 接口权限
 * @param permissions
 * @returns SetMetadata
 */
export const RequirePermission = (...permissions: string[]) =>
  SetMetadata('require-permission', permissions);

/**
 * @description 自定义参数装饰器
 * @returns 传入 UserInfo 的属性名返回对应属性值，不穿返回所有
 */
export const UserInfo = createParamDecorator(
  (data: string, ctx: ExecutionContext) => {
    const request: Request = ctx.switchToHttp().getRequest();
    if (!request.user) return null;
    return data ? request.user[data] : request.user;
  },
);
