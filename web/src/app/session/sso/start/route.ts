import { ssoStart } from '@/lib/sso';
export const GET = (request: Request) => ssoStart(request);
export const dynamic = 'force-dynamic';
