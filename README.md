# GFA Fleet Control - Backend

API FastAPI para sistema de controle de frotas.

## Deploy no Railway

### Variáveis de Ambiente Necessárias

```env
MYSQL_HOST=br562.hostgator.com.br
MYSQL_PORT=3306
MYSQL_USER=gfane159_fleetuser
MYSQL_PASSWORD=147963As$#
MYSQL_DATABASE=gfane159_fleet
JWT_SECRET=gfa-fleet-control-secret-key-2024-secure
PORT=8001
```

### Procfile
O arquivo `Procfile` já está configurado para rodar com Uvicorn.

## Endpoints

- `POST /api/auth/login` - Login via API externa GFA
- `GET /api/vehicles` - Listar veículos
- `POST /api/vehicles` - Criar veículo
- `GET /api/fuel-refuelings` - Listar abastecimentos
- `POST /api/fuel-refuelings` - Registrar abastecimento
- `GET /api/vehicles/{id}/report` - Relatório do veículo
