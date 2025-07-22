// src/app/creator/layout.tsx
import { getServerSession } from "next-auth";
import { authOptions } from "@/src/app/api/auth/[...nextauth]/route";
import { redirect } from "next/navigation";
import Link from "next/link";

export default async function CreatorLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const session = await getServerSession(authOptions);

  // Si no hay sesión o no es creador, redirigir al login
  if (!session || !session.user?.isCreator) {
    redirect("/login?callbackUrl=/creator/dashboard");
  }

  return (
    <div style={{ display: 'flex' }}>
      <aside style={{ width: '200px', padding: '20px', backgroundColor: '#2a2a2a', borderRight: '1px solid #333' }}>
        <h3 style={{ color: '#00e676' }}>Panel Creador</h3>
        <nav>
          <ul style={{ listStyle: 'none', padding: 0 }}>
            <li style={{ marginBottom: '10px' }}><Link href="/creator/dashboard">Dashboard</Link></li>
            <li style={{ marginBottom: '10px' }}><Link href="/creator/live-studio">Estudio en Vivo</Link></li>
            <li style={{ marginBottom: '10px' }}><Link href="/creator/publications">Publicaciones</Link></li>
            <li style={{ marginBottom: '10px' }}><Link href="/creator/rewards">Recompensas</Link></li>
            <li style={{ marginBottom: '10px' }}><Link href="/creator/payouts">Pagos</Link></li>
          </ul>
        </nav>
      </aside>
      <main style={{ flexGrow: 1, padding: '20px' }}>
        {children}
      </main>
    </div>
  );
}
