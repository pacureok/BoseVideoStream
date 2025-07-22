// src/app/api/streamer-info/route.ts
import { NextResponse } from 'next/server';
import { query } from '@/src/lib/db'; // CORREGIDO AQUÍ: Añade 'src/'

export async function GET(req: Request) {
  const url = new URL(req.url);
  const username = url.searchParams.get('username');

  if (!username) {
    return NextResponse.json({ message: 'Nombre de usuario requerido.' }, { status: 400 });
  }

  try {
    const userRes = await query("SELECT id, username, youtube_url, is_live FROM users WHERE username = $1", [username]);
    const streamer = userRes.rows[0];

    if (!streamer) {
      return NextResponse.json({ message: 'Streamer no encontrado.' }, { status: 404 });
    }

    return NextResponse.json({ streamer });
  } catch (error) {
    console.error('Error al obtener info del streamer:', error);
    return NextResponse.json({ message: 'Error interno del servidor.' }, { status: 500 });
  }
}
