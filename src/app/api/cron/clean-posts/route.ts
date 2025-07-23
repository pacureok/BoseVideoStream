// src/app/api/cron/clean-posts/route.ts

import { NextResponse } from 'next/server';

import { query } from '@/src/lib/db'; // CORREGIDO AQUÍ: Añade 'src/'



export async function GET(req: Request) {

  // Proteger esta ruta para que solo sea accesible por Vercel Cron Job o una clave secreta

  // if (req.headers.get('Authorization') !== `Bearer ${process.env.CRON_SECRET}`) {

  //   return NextResponse.json({ message: 'Unauthorized' }, { status: 401 });

  // }



  try {

    const thirtyDaysAgo = new Date();

    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);



    const res = await query("DELETE FROM creator_posts WHERE created_at < $1", [thirtyDaysAgo]);

    console.log(`Eliminados ${res.rowCount} publicaciones antiguas.`);



    return NextResponse.json({ message: `Eliminados ${res.rowCount} publicaciones antiguas.` });

  } catch (error) {

    console.error('Error al limpiar publicaciones antiguas:', error);

    return NextResponse.json({ message: 'Error interno del servidor.' }, { status: 500 });

  }

}
