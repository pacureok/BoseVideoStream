// src/app/api/creator/publications/route.ts
import { NextResponse } from 'next/server';
import { getServerSession } from "next-auth";
import { authOptions } from "@/src/app/api/auth/[...nextauth]/route";
import { query } from '@/src/lib/db';

// GET para obtener publicaciones de un creador (se usará en la página del streamer)
export async function GET(req: Request) {
  const url = new URL(req.url);
  const creatorId = url.searchParams.get('creatorId');

  if (!creatorId) {
    return NextResponse.json({ message: 'ID de creador requerido.' }, { status: 400 });
  }

  try {
    const posts = await query("SELECT * FROM creator_posts WHERE creator_id = $1 ORDER BY created_at DESC", [creatorId]);
    return NextResponse.json(posts.rows);
  } catch (error) {
    console.error('Error al obtener publicaciones:', error);
    return NextResponse.json({ message: 'Error interno del servidor.' }, { status: 500 });
  }
}

// POST para crear una nueva publicación (solo creadores)
export async function POST(req: Request) {
  const session = await getServerSession(authOptions);
  if (!session || !session.user?.isCreator) {
    return NextResponse.json({ message: 'No autorizado.' }, { status: 403 });
  }

  try {
    const { type, content } = await req.json(); // type: 'text' o 'youtube_url'

    if (!type || !content) {
      return NextResponse.json({ message: 'Tipo y contenido son requeridos.' }, { status: 400 });
    }

    await query(
      "INSERT INTO creator_posts (creator_id, type, content) VALUES ($1, $2, $3)",
      [session.user.id, type, content]
    );

    return NextResponse.json({ message: 'Publicación creada exitosamente.' }, { status: 201 });
  } catch (error) {
    console.error('Error al crear publicación:', error);
    return NextResponse.json({ message: 'Error interno del servidor.' }, { status: 500 });
  }
}

// DELETE (opcional) para eliminar una publicación (solo creadores)
export async function DELETE(req: Request) {
    const session = await getServerSession(authOptions);
    if (!session || !session.user?.isCreator) {
        return NextResponse.json({ message: 'No autorizado.' }, { status: 403 });
    }

    try {
        const { postId } = await req.json();

        if (!postId) {
            return NextResponse.json({ message: 'ID de publicación requerido.' }, { status: 400 });
        }

        // Asegurarse de que el creador solo pueda eliminar sus propias publicaciones
        await query("DELETE FROM creator_posts WHERE id = $1 AND creator_id = $2", [postId, session.user.id]);

        return NextResponse.json({ message: 'Publicación eliminada.' });
    } catch (error) {
        console.error('Error al eliminar publicación:', error);
        return NextResponse.json({ message: 'Error interno del servidor.' }, { status: 500 });
    }
}
