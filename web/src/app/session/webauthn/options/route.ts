import { passkeyOptions } from '@/lib/passkey';
export const POST = (request: Request) => passkeyOptions(request);
export const dynamic = 'force-dynamic';
