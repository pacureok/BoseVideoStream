// src/app/creator/live-studio/page.tsx
'use client';
import { useState, useEffect } from 'react';
import { useSession } from 'next-auth/react';
import Pusher from 'pusher-js'; // Para el frontend
import { query } from "@/src/lib/db"; // Esto es para usarlo en el servidor si hubiera API routes directas

export default function LiveStudioPage() {
  const { data: session, status } = useSession();
  const [streamKey, setStreamKey] = useState('');
  const [youtubeUrl, setYoutubeUrl] = useState('');
  const [isLive, setIsLive] = useState(false);
  const [chatMessages, setChatMessages] = useState<string[]>([]);
  const [newChatMessage, setNewChatMessage] = useState('');

  useEffect(() => {
    if (status === 'authenticated' && session.user?.id) {
      // Cargar datos del creador (stream key, youtubeUrl, etc.)
      fetch(`/api/creator/stream-info?userId=${session.user.id}`) // Crear esta API Route
        .then(res => res.json())
        .then(data => {
          if (data.streamKey) setStreamKey(data.streamKey);
          if (data.youtubeUrl) setYoutubeUrl(data.youtubeUrl);
          // Podrías cargar el estado 'isLive' también si lo guardas en la DB
        });

      // Inicializar Pusher para el chat (en el cliente)
      const pusher = new Pusher(process.env.NEXT_PUBLIC_PUSHER_KEY || '', {
        cluster: process.env.NEXT_PUBLIC_PUSHER_CLUSTER || 'us2',
      });

      // Suscribirse al canal de chat del creador
      const channel = pusher.subscribe(`chat-${session.user.id}`);
      channel.bind('new-message', (data: { message: string }) => {
        setChatMessages((prev) => [...prev, data.message]);
      });

      return () => {
        channel.unsubscribe();
        pusher.disconnect();
      };
    }
  }, [session, status]);

  const handleGoLive = async () => {
    // Enviar al backend que el creador está "en vivo"
    await fetch('/api/live', { // Crear esta API Route
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: session?.user?.id, status: true, youtubeUrl }),
    });
    setIsLive(true);
    alert('¡Estás en vivo!');
  };

  const handleEndLive = async () => {
    // Enviar al backend que el creador ya NO está "en vivo"
    await fetch('/api/live', { // Crear esta API Route
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: session?.user?.id, status: false }),
    });
    setIsLive(false);
    alert('Transmisión finalizada.');
  };

  const handleSendChatMessage = async () => {
    if (!newChatMessage.trim()) return;
    // Enviar el mensaje del creador al chat (a través de una API route que usa Pusher)
    await fetch('/api/chat/send', { // Crear esta API Route
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        userId: session?.user?.id,
        creatorId: session?.user?.id, // El creador envía al su propio canal
        message: `${session?.user?.name}: ${newChatMessage}`,
      }),
    });
    setNewChatMessage('');
  };

  if (status === 'loading') {
    return <p>Cargando estudio...</p>;
  }

  if (!session || !session.user?.isCreator) {
    return <p>Acceso denegado. Debes ser un creador para acceder al estudio en vivo.</p>;
  }

  return (
    <div>
      <h2>Estudio en Vivo de {session.user.name}</h2>

      <section>
        <h3>Configuración de Transmisión</h3>
        <p>Tu clave de transmisión para OBS: <code>{streamKey || 'Generando...'}</code></p>
        <button /* onClick para generar/regenerar streamKey */>Generar Nueva Clave</button>
        <p>
          URL de transmisión principal (RTMP URL): `rtmp://live.bosevideostream.com/app` (Esto sería si tuvieras tu propio servidor RTMP, **para un MVP gratuito, esta URL es la de Restream.io o YouTube, y se la darías al creador)**
        </p>
        <p>Para multi-stream, usa **Restream.io** o **StreamYard** y conéctalos a tu clave de BoseVideoStream.</p>
        <label>
          URL de tu transmisión de YouTube (para embeber):
          <input
            type="text"
            value={youtubeUrl}
            onChange={(e) => setYoutubeUrl(e.target.value)}
            placeholder="Ej: https://www.youtube.com/embed/XXXXXX"
            style={{ width: '100%', maxWidth: '400px', display: 'block' }}
          />
        </label>
        <button onClick={() => {/* guardar youtubeUrl en la DB */}}>Guardar URL YouTube</button>
        <br />
        {isLive ? (
          <button onClick={handleEndLive} style={{ backgroundColor: 'red' }}>Finalizar Transmisión</button>
        ) : (
          <button onClick={handleGoLive} style={{ backgroundColor: 'green' }}>Iniciar Transmisión Ahora</button>
        )}
      </section>

      <section>
        <h3>Previsualización del Stream</h3>
        {youtubeUrl && (
          <div style={{ position: 'relative', width: '100%', paddingBottom: '56.25%', height: 0 }}>
            <iframe
              src={youtubeUrl}
              frameBorder="0"
              allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
              allowFullScreen
              style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%' }}
              title="YouTube Stream"
            ></iframe>
          </div>
        )}
        {!youtubeUrl && <p>Introduce una URL de YouTube para previsualizar tu stream.</p>}
      </section>

      <section>
        <h3>Chat en Vivo</h3>
        <div style={{ border: '1px solid #444', height: '300px', overflowY: 'scroll', padding: '10px', backgroundColor: '#333' }}>
          {chatMessages.map((msg, index) => (
            <p key={index}>{msg}</p>
          ))}
        </div>
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
      </section>
    </div>
  );
}
