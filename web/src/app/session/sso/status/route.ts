import { ssoStatus } from '@/lib/sso';
export const GET = (request: Request) => ssoStatus(request);
export const dynamic = 'force-dynamic';
