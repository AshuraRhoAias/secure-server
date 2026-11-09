import { passkeyLogin } from '@/lib/passkey';
export const POST = (request: Request) => passkeyLogin(request);
export const dynamic = 'force-dynamic';
