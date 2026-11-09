import { cookies } from 'next/headers';
import type { ReactNode } from 'react';
import { Shell } from '@/components/Shell';
import { sessionCookieName } from '@/lib/config';
import { readSession } from '@/lib/session';

export default async function OpsLayout({ children }: { children: ReactNode }) {
  const store = await cookies();
  const session = readSession(store.get(sessionCookieName())?.value);
  return <Shell user={session?.u ?? 'administrador'}>{children}</Shell>;
}
