import { me } from '@/lib/bff';
export const GET = (request: Request) => me(request);
export const dynamic = 'force-dynamic';
