import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "@/src/styles/globals.css"; // Importa tus estilos globales
import { SessionProvider } from "next-auth/react"; // Necesitas este para NextAuth

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "BoseVideoStream",
  description: "Plataforma de streaming de video y audio de alta calidad.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="es">
      <body className={inter.className}>
        <SessionProvider> {/* Envuelve tu app con SessionProvider */}
          <header style={{ backgroundColor: '#333', padding: '15px', color: 'white', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h1 style={{ margin: 0, color: '#00e676' }}>BoseVideoStream</h1>
            <nav>
              <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', gap: '20px' }}>
                <li><a href="/">Inicio</a></li>
                <li><a href="/info">Información</a></li>
                <li><a href="/login">Iniciar Sesión</a></li>
                <li><a href="/register">Registrarse</a></li>
                {/* Aquí puedes añadir lógica para mostrar "Panel Creador" si está logueado */}
              </ul>
            </nav>
          </header>
          <main style={{ padding: '20px' }}>
            {children}
          </main>
        </SessionProvider>
      </body>
    </html>
  );
}
