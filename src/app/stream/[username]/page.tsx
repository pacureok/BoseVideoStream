// src/app/stream/[username]/page.tsx
'use client';
import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import Pusher from 'pusher-js'; // Para el frontend
import { useSession } from 'next-auth/react'; // Para el usuario que chatea

interface StreamerData {
  id: string;
  username: string;
  youtube_url?: string;
  is_live: boolean;
}

export default function StreamPage() {
  const params = useParams();
  const username = params.username as string;
  const { data: session } = useSession();
  const [streamer, setStreamer] = useState<StreamerData | null>(null);
  const [chatMessages, setChatMessages] = useState<string[]>([]);
  const [newChatMessage, setNewChatMessage] = useState('');

  useEffect(() => {
    if (!username) return;

    // Cargar datos del streamer por username
    fetch(`/api/streamer-info?username=${username}`) // Crear esta API Route
      .then(res => res.json())
      .then(data => {
        if (data.streamer) {
          setStreamer(data.streamer);
          // Inicializar Pusher para el chat del streamer
          const pusher = new Pusher(process.env.NEXT_PUBLIC_PUSHER_KEY || '', {
            cluster: process.env.NEXT_PUBLIC_PUSHER_CLUSTER || 'us2',
          });

          const channel = pusher.subscribe(`chat-${data.streamer.id}`);
          channel.bind('new-message', (data: { message: string }) => {
            setChatMessages((prev) => [...prev, data.message]);
          });

          return () => {
            channel.unsubscribe();
            pusher.disconnect();
          };
        }
      });
  }, [username]);

  const handleSendChatMessage = async () => {
    if (!newChatMessage.trim() || !streamer || !session?.user) return;

    await fetch('/api/chat/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: newChatMessage,
        creatorId: streamer.id, // El ID del creador al que le estoy chateando
      }),
    });
    setNewChatMessage('');
  };

  if (!streamer) {
    return <p>Cargando información del streamer o streamer no encontrado...</p>;
  }

  return (
    <div style={{ display: 'flex', gap: '20px', maxWidth: '1200px', margin: 'auto' }}>
      <div style={{ flex: 2 }}>
        <h2>Stream de {streamer.username} {streamer.is_live ? '(EN VIVO)' : '(OFFLINE)'}</h2>
        {streamer.youtube_url && (
          <div style={{ position: 'relative', width: '100%', paddingBottom: '56.25%', height: 0, marginBottom: '20px' }}>
            <iframe
              src={streamer.youtube_url}
              frameBorder="0"
              allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
              allowFullScreen
              style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%' }}
              title={`${streamer.username} Stream`}
            ></iframe>
          </div>
        )}
        {!streamer.youtube_url && <p>Este creador no tiene una URL de YouTube configurada para su transmisión.</p>}

        <section>
          <h3>Publicaciones del Creador</h3>
          {/* Aquí mostrarías las publicaciones/URLs que el creador ha hecho */}
          <p>Publicaciones aquí...</p>
        </section>
      </div>

      <div style={{ flex: 1, backgroundColor: '#2a2a2a', padding: '15px', borderRadius: '8px', display: 'flex', flexDirection: 'column' }}>
        <h3>Chat del Stream</h3>
        <div style={{ border: '1px solid #444', height: '400px', overflowY: 'scroll', padding: '10px', backgroundColor: '#333', flexGrow: 1 }}>
          {chatMessages.map((msg, index) => (
            <p key={index}>{msg}</p>
          ))}
        </div>
        {session ? ( // Solo muestra el input si el usuario está logueado
          <div style={{ display: 'flex', marginTop: '10px' }}>
            <input
              type="text"
              value={newChatMessage}
              onChange={(e) => setNewChatMessage(e.target.value)}
              placeholder="Escribe un mensaje..."
              style={{ flexGrow: 1, marginRight: '10px' }}
            />
            <button onClick={handleSendChatMessage}>Enviar</button>
          </div>
        ) : (
          <p style={{ textAlign: 'center', marginTop: '10px' }}>Inicia sesión para chatear.</p>
        )}
      </div>
    </div>
  );
}
