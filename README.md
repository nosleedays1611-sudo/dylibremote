# RemoteAuth — REMOTE iOS

Auth separada em dylib, no mesmo modelo arquitetural usado pela EXTERNAL.

## Autoridade

- API base da dylib: `https://remoteios.xyz`
- Gerador consultado pelo backend: `https://rafaelagenerator.shardweb.app`
- Formato da key: `REMOTE-IOS-XXXXXX`
- Vínculo: KEY + IPv4 público observado pelo backend.
- A dylib **não envia um IPv4 escolhido pelo cliente** para autorizar a key.

## Endpoints usados pela dylib

- `POST /api/auth/activate` body: `{ "key": "REMOTE-IOS-XXXXXX" }`
- `GET /api/auth/me` com `Authorization: Bearer <token>`
- `POST /api/auth/check` com `Authorization: Bearer <token>`
- `POST /api/auth/logout` com `Authorization: Bearer <token>`

Códigos tratados: `invalid_key`, `invalid_key_format`, `expired`, `paused`, `disabled`, `ipv4_mismatch`, `unauthorized`, `session_revoked`.

## Fluxo

1. A dylib abre o overlay ao ser carregada.
2. O usuário informa apenas a key.
3. `/api/auth/activate` recebe a key e o backend obtém o IPv4 da própria requisição.
4. O backend consulta a RAFAELA em `/api/client/activate` usando KEY + IPv4 observado.
5. Se a key estiver `unused`, a RAFAELA inicia a validade e vincula o IPv4.
6. O backend retorna JWT de sessão + key + IPv4.
7. A dylib salva key e token no Keychain.
8. A cada 20 s, `/api/auth/check` revalida sessão/licença/IP.
9. Se key/IP/status deixarem de ser válidos, o overlay volta e o app fica bloqueado.

## Build

O workflow é `.github/workflows/build-remote-auth.yml`.

Saída:

- `build/RemoteAuth.dylib`
- `build/RemoteAuth.dylib.zip`
- `build/RemoteAuth.dylib.sha256.txt`

A dylib usa install name `@rpath/RemoteAuth.dylib` e embute `icon.gif` na seção Mach-O `__DATA,__eaicon`.

## Backend incluído

`backend/server.js` é a versão do server REMOTE ajustada para este fluxo. Ela:

- detecta o IPv4 no servidor via `req.ip`/socket;
- não usa `req.body.ipv4` como autoridade;
- mantém `RAFAELA_API_URL` separado;
- implementa os 4 endpoints finais;
- amarra o JWT ao IPv4;
- revalida a licença na RAFAELA;
- persiste revogação de sessão para `/api/auth/logout`;
- preserva as demais rotas/configurações do server atual.

`site/index.html` também foi alinhado: o login envia apenas a key e o logout chama `/api/auth/logout`. A detecção via ipify ficou apenas visual e não é usada como autoridade.

## Segredos

Não há `JWT_SECRET`, senha admin ou `REMOTE_SESSION_SECRET` dentro da dylib. O segredo de sessão fica somente no backend.
