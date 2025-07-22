// src/app/api/creator/stream-info/route.ts
import { NextResponse } from 'next/server';
import { getServerSession } from "next-auth";
import { authOptions } from "@/src/app/api/auth/[...nextauth]/route";
import { query } from '@/src/lib/db';
import { v4 as uuidv4 } from 'uuid'; // Necesitarás instalar 'uuid' para generar claves

// GET para obtener la info del creador
export async function GET(req: Request) {
  const session = await getServerSession(authOptions);
  if (!session || !session.user?.isCreator) {
    return NextResponse.json({ message: 'No autorizado.' }, { status: 403 });
  }

  try {
    const userRes = await query("SELECT stream_key, youtube_url FROM users WHERE id = $1", [session.user.id]);
    const creatorData = userRes.rows[0];
    return NextResponse.json({ streamKey: creatorData?.stream_key, youtubeUrl: creatorData?.youtube_url });
  } catch (error) {
    console.error('Error al obtener info de stream:', error);
    return NextResponse.json({ message: 'Error interno del servidor.' }, { status: 500 });
  }
}

// POST para actualizar la info del creador (stream key o youtube url)
export async function POST(req: Request) {
  const session = await getServerSession(authOptions);
  if (!session || !session.user?.isCreator) {
    return NextResponse.json({ message: 'No autorizado.' }, { status: 403 });
  }

  try {
    const { type, value } = await req.json(); // type: 'streamKey' o 'youtubeUrl'

    if (type === 'streamKey') {
      const newStreamKey = uuidv4(); // Genera una nueva clave única
      await query("UPDATE users SET stream_key = $1 WHERE id = $2", [newStreamKey, session.user.id]);
      return NextResponse.json({ message: 'Clave de stream actualizada.', streamKey: newStreamKey });
    } else if (type === 'youtubeUrl') {
      await query("UPDATE users SET youtube_url = $1 WHERE id = $2", [value, session.user.id]);
      return NextResponse.json({ message: 'URL de YouTube actualizada.' });
    } else {
      return NextResponse.json({ message: 'Tipo de actualización no válido.' }, { status: 400 });
    }

  } catch (error) {
    console.error('Error al actualizar info de stream:', error);
    return NextResponse.json({ message: 'Error interno del servidor.' }, { status: 500 });
  }
}
