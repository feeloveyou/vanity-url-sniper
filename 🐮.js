"use strict"; // Katı modda çalıştır (hataları daha erken yakalar)
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"; // TLS sertifika doğrulamasını kapat (güvenli değil ama hız için kullanılıyor)

const WebSocket = require('ws'); // Discord gateway bağlantısı için WebSocket modülü
const tls = require('tls');       // TLS (SSL) üzerinden raw soket bağlantısı
const fs = require('fs');         // Dosya işlemleri için filesystem modülü

// Konfigürasyon ayarları
const config = {
    token: "", // Discord hesabı tokeni
    serverid: "1393195630683357204" // Hedef Discord sunucusunun ID'si
};

// Global değişkenler
const guilds = new Map();         // Sunucuların vanity URL kodlarını tutar
const ownGuildVanities = new Set(); // Kullanıcıya ait vanity kodlarını saklar
let mfa = null;                   // MFA tokeni (2FA doğrulaması)
let lastSeq = null;               // Discord gateway sequence ID
let hbInterval = null;            // Gateway heartbeat interval
const tlsConnections = [];        // TLS socket havuzu
let index = 0;                    // Round-robin index

// HTTP isteklerinde kullanılacak sabit header’lar
const headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
    'Authorization': config.token,
    'Host': 'canary.discord.com',
    'Connection': 'keep-alive',
    'X-Super-Properties': '...' // Discord’un client fingerprint datası (base64 json)
};

// TLS soketi oluşturma fonksiyonu
function createSocket(id) {
    return new Promise((resolve) => {
        const socket = tls.connect({
            host: 'canary.discord.com',
            port: 443,
            // Kullanılacak TLS şifre paketleri
            ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305',
            secureProtocol: 'TLSv1_2_method',
            rejectUnauthorized: false // Sertifika doğrulamasını kapat
        });
        socket.setKeepAlive(true, 0); // Sürekli bağlantı
        socket.setNoDelay(true);      // TCP paketlerini hemen gönder
        socket.setTimeout(0);         // Timeout yok
        socket.id = id;
        socket.ready = false;
        
        // Bağlantı açıldığında
        socket.on('secureConnect', () => {
            socket.ready = true;
            resolve(socket);
        });
        
        // Bağlantı kapanırsa tekrar oluştur
        socket.on('close', () => {
            socket.ready = false;
            setTimeout(() => createSocket(id).then(s => tlsConnections[id] = s), 100);
        });
        
        // Hata olursa tekrar oluştur
        socket.on('error', () => {
            socket.ready = false;
            setTimeout(() => createSocket(id).then(s => tlsConnections[id] = s), 100);
        });
    });
}

// TLS socket havuzunu başlat (7 adet bağlantı açıyor)
function initSockets() {
    for (let i = 0; i < 7; i++) {
        createSocket(i).then(socket => tlsConnections[i] = socket);
    }
}

// Normal HTTP istek fonksiyonu
function request(method, path, customHeaders = {}, body = null) {
    const socket = tlsConnections[index]; // Round-robin seçimi
    index = (index + 1) % tlsConnections.length;
    
    return new Promise((resolve, reject) => {
        if (!socket || !socket.ready) {
            return reject(new Error('Socket not ready'));
        }
        
        const h = { ...headers, ...customHeaders };
        if (body) h['Content-Length'] = Buffer.byteLength(body);
        
        // HTTP isteği string olarak hazırlanıyor
        let req = `${method} ${path} HTTP/1.1\r\n`;
        Object.entries(h).forEach(([k, v]) => req += `${k}: ${v}\r\n`);
        req += '\r\n' + (body || '');
        
        let rawResponse = '';
        let done = false;
        
        // Cevap geldiğinde
        const onData = (chunk) => {
            if (done) return;
            rawResponse += chunk.toString();
            if (rawResponse.includes('\r\n\r\n')) {
                const parts = rawResponse.split('\r\n\r\n');
                let bodyPart = parts.slice(1).join('\r\n\r\n'); // Body kısmını al
                done = true;
                socket.removeListener('data', onData);
                resolve(bodyPart);
            }
        };
        
        socket.on('data', onData);
        socket.write(req); // İstek gönder
    });
}

// Daha hızlı HTTP isteği (timeout eklenmiş)
function ultrafastrequest(method, path, customHeaders = {}, body = null) {
    const socket = tlsConnections[index];
    index = (index + 1) % tlsConnections.length;
    
    return new Promise((resolve, reject) => {
        if (!socket || !socket.ready) {
            return reject(new Error('Socket not ready'));
        }
        
        const h = { ...headers, ...customHeaders };
        if (body) h['Content-Length'] = Buffer.byteLength(body);
        
        let req = `${method} ${path} HTTP/1.1\r\n`;
        Object.entries(h).forEach(([k, v]) => req += `${k}: ${v}\r\n`);
        req += '\r\n' + (body || '');
        
        let rawResponse = '';
        let done = false;
        
        // 500ms timeout koyulmuş
        const timeout = setTimeout(() => {
            if (!done) {
                done = true;
                socket.removeListener('data', onData);
                reject(new Error('Timeout'));
            }
        }, 500);
        
        const onData = (chunk) => {
            if (done) return;
            rawResponse += chunk.toString();
            if (rawResponse.includes('\r\n\r\n')) {
                const parts = rawResponse.split('\r\n\r\n');
                let bodyPart = parts.slice(1).join('\r\n\r\n');
                done = true;
                clearTimeout(timeout);
                socket.removeListener('data', onData);
                resolve(bodyPart);
            }
        };
        
        socket.on('data', onData);
        socket.write(req);
    });
}

// MFA tokenini dosyadan okur (mfa_token.json)
function readMfaToken() {
    try {
        if (fs.existsSync('./mfa_token.json')) {
            const data = JSON.parse(fs.readFileSync('./mfa_token.json', 'utf8'));
            if (data.token && data.token !== mfa) {
                mfa = data.token;
                console.log('mfa gecildi');
            }
        }
    } catch {}
}

// Vanity URL snipe fonksiyonu
function instantSnipe(url) {
    if (!mfa) return; // MFA token yoksa dur
    
    const payload = JSON.stringify({ code: url });
    const snipeHeaders = {
        'X-Discord-MFA-Authorization': mfa,
        'Content-Type': 'application/json'
    };
    
    // 6 paralel PATCH isteği oluşturuluyor
    const requests = Array.from({ length: 6 }, () =>
        ultrafastrequest('PATCH', `/api/v7/guilds/${config.serverid}/vanity-url`, snipeHeaders, payload)
            .then(res => {
                try {
                    const data = JSON.parse(res);
                    if (data.code === url) {
                        console.log(`✓ Başarılı: ${url}`);
                        return { success: true, data, url };
                    }
                } catch {}
                throw new Error('Başarısız istek');
            })
    );
    
    // İlk başarılı isteği bekle (Promise.race)
    Promise.race(requests)
        .then(result => {
            console.log(`✓ Başarılı: ${url}`);
        })
        .catch(() => {
            // Eğer ilk başarısızsa, diğerlerinden herhangi biri başarılı olabilir (Promise.any)
            Promise.any(requests)
                .then(result => {
                    console.log(`✓ Başarılı: ${url}`);
                })
                .catch(error => {
                    // Hiçbiri başarılı değil
                });
        });
}

// Discord Gateway bağlantısı
function connectWS() {
    const ws = new WebSocket('wss://gateway-us-east1-b.discord.gg/?v=9&encoding=json');
    
    ws.on('open', () => {
        // Kimlik doğrulama paketi gönder
        ws.send(JSON.stringify({
            op: 2,
            d: {
                token: config.token,
                intents: 1,
                properties: {
                    $os: "linux",
                    $browser: "",
                    $device: ""
                }
            }
        }));
    });
    
    ws.on('message', (data) => {
        try {
            const msg = JSON.parse(data);
            if (msg.s) lastSeq = msg.s;
            
            if (msg.op === 10) {
                // Heartbeat başlat
                clearInterval(hbInterval);
                hbInterval = setInterval(() => {
                    if (ws.readyState === 1) {
                        ws.send(JSON.stringify({ op: 1, d: lastSeq }));
                    }
                }, msg.d.heartbeat_interval * 0.4); // Normalde 1x ama burada 0.4x hız
            }
            
            if (msg.op === 0) { // Dispatch event
                if (msg.t === 'READY') {
                    // Kullanıcının sunucularını takip et
                    msg.d.guilds.filter(g => g.vanity_url_code).forEach(g => {
                        guilds.set(g.id, g.vanity_url_code);
                        if (g.owner_id === msg.d.user.id || (g.permissions && (parseInt(g.permissions) & 8) === 8)) {
                            ownGuildVanities.add(g.vanity_url_code);
                        }
                        console.log(`Tracked: ${g.vanity_url_code}`);
                    });
                }
                
                if (msg.t === 'GUILD_UPDATE') {
                    // Vanity URL değişmişse snipe denemesi yap
                    const stored = guilds.get(msg.d.id);
                    if (stored && (stored !== msg.d.vanity_url_code || (!msg.d.vanity_url_code && ownGuildVanities.has(stored)))) {
                        console.log(` Sniping: ${stored}`);
                        instantSnipe(stored);
                    }
                    
                    // Yeni vanity varsa güncelle
                    if (msg.d.vanity_url_code) {
                        guilds.set(msg.d.id, msg.d.vanity_url_code);
                    }
                }
            }
        } catch {}
    });
    
    ws.on('close', () => {
        clearInterval(hbInterval);
        setTimeout(connectWS, 300); // Bağlantı kapanırsa yeniden bağlan
    });
    
    ws.on('error', () => ws.close());
}

// Başlatıcı fonksiyon
function init() {
    initSockets(); // TLS soketleri başlat
    
    readMfaToken();
    if (fs.existsSync('./mfa_token.json')) {
        fs.watchFile('./mfa_token.json', { interval: 50 }, readMfaToken); // Dosya değişirse oku
    }
    setInterval(readMfaToken, 100);
    
    // 3 farklı gateway bağlantısı aç
    for (let i = 0; i < 3; i++) {
        setTimeout(() => connectWS(), i * 30);
    }
}

setTimeout(init, 100);

// CTRL+C basılınca temiz çıkış
process.on('SIGINT', () => {
    tlsConnections.forEach(s => s.destroy());
    process.exit(0);
});
