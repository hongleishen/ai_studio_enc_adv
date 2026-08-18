const http = require('http');

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(`
    <html>
      <head>
        <title>ESP-IDF Workspace</title>
        <style>
          body { font-family: system-ui, sans-serif; padding: 2rem; line-height: 1.5; color: #333; }
          .container { max-w: 800px; margin: 0 auto; }
          h1 { color: #e63946; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>乐鑫 C 工程工作区 (ESP-IDF Workspace)</h1>
          <p>这是一个纯 C 语言工程。当前网页服务器仅用于维持 AI Studio 开发环境的运行。</p>
          <p>请在右侧聊天窗口发送指令，我们将直接对代码进行修改，无需在此环境中编译。</p>
        </div>
      </body>
    </html>
  `);
});

const port = process.env.PORT || 3000;
server.listen(port, () => {
  console.log('Dummy server listening on port ' + port);
});
