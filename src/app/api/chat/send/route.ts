// src/app/api/chat/send/route.ts

import { NextResponse } from 'next/server';

import { getServerSession } from "next-auth";

import { authOptions } from "@/src/app/api/auth/[...nextauth]/route"; // CORREGIDO AQUÍ: Añade 'src/'

import Pusher from 'pusher'; // Para el backend



// Configurar Pusher en el backend

const pusher = new Pusher({

  appId: process.env.PUSHER_APP_ID || '',

  key: process.env.NEXT_PUBLIC_PUSHER_KEY || '', // Usa NEXT_PUBLIC_ si lo compartes con el frontend

  secret: process.env.PUSHER_SECRET || '',

  cluster: process.env.NEXT_PUBLIC_PUSHER_CLUSTER || 'us2',

  useTLS: true,

});



export async function POST(req: Request) {

  const session = await getServerSession(authOptions);

  if (!session) { // Puedes restringir quién puede chatear

    return NextResponse.json({ message: 'No autenticado.' }, { status: 401 });

  }



  try {

    const { message, creatorId } = await req.json(); // creatorId es el ID del canal al que se envía



    if (!message || !creatorId) {

      return NextResponse.json({ message: 'Mensaje y ID de creador son requeridos.' }, { status: 400 });

    }



    // El mensaje se envía al canal del creador

    await pusher.trigger(`chat-${creatorId}`, 'new-message', {

      message: `${session.user?.name}: ${message}`,

    });



    return NextResponse.json({ message: 'Mensaje enviado.' });

  } catch (error) {

    console.error('Error al enviar mensaje de chat:', error);

    return NextResponse.json({ message: 'Error interno del servidor.' }, { status: 500 });

  }

}
