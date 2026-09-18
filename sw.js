self.addEventListener('push', function(event) {
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(windowClients => {
      if (windowClients && windowClients.length > 0) {
        // If the user has any BetterChat window open, suppress the Web Push notification
        // because the active page's polling will trigger a local Notification if hidden,
        // or no notification at all if focused!
        return Promise.resolve();
      }

      return fetch('/api.php?action=get_offline_notifications', { credentials: 'same-origin' })
        .then(res => res.json())
        .then(data => {
          let title = 'New Notification';
          let body = 'You have new activity in BetterChat.';
            
          if(data.ok && data.message) {
            const m = data.message;
            title = m.type.startsWith('dm_') ? `DM from ${m.username}` : `${m.username} in #${m.name}`;
            body = m.content || 'Sent an attachment';
            if (m.msg_type === 'image') body = 'Sent an image';
            if (m.msg_type === 'file') body = 'Sent a file';
            if (m.msg_type === 'webrtc' && m.content.includes('"call_request"')) {
              body = '📞 Is calling you...';
            }
          }

          return self.registration.showNotification(title, {
            body: body,
            icon: '/favicon.ico',
            badge: '/favicon.ico',
            data: { url: '/' }
          });
        }).catch(err => {
          return self.registration.showNotification("New Message", {
            body: "You have a new message on BetterChat.",
            icon: '/favicon.ico'
          });
        });
    })
  );
});

self.addEventListener('notificationclick', function(event) {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: 'window' }).then(windowClients => {
      for (let i = 0; i < windowClients.length; i++) {
        let client = windowClients[i];
        if (client.url.includes('chat.php') && 'focus' in client) {
          return client.focus();
        }
      }
      if (clients.openWindow) {
        return clients.openWindow('/chat.php');
      }
    })
  );
});
