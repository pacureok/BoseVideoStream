import { NextResponse } from 'next/server';
import { hashPassword } from '@/lib/auth'; // Importamos la función de hash
import { query } from '@/lib/db';

export async function POST(req: Request) {
  try {
    const { username, password } = await req.json(); // Solo username y password

    if (!username || !password) {
      return NextResponse.json({ message: 'Nombre de usuario y contraseña son requeridos.' }, { status: 400 });
    }

    const hashedPassword = await hashPassword(password);

    await query(
      "INSERT INTO users (username, password) VALUES ($1, $2)", // Solo username y password
      [username, hashedPassword]
    );

    return NextResponse.json({ message: 'Usuario registrado exitosamente.' }, { status: 201 });

  } catch (error: any) {
    if (error.code === '23505') { // Código de error de PostgreSQL para clave única duplicada (username)
      return NextResponse.json({ message: 'El nombre de usuario ya está registrado.' }, { status: 409 });
    }
    console.error('Error al registrar usuario:', error);
    return NextResponse.json({ message: 'Error interno del servidor.' }, { status: 500 });
  }
}
