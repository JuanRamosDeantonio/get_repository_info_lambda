# 🧠 Source Code Repository Manager

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![AWS Lambda](https://img.shields.io/badge/AWS-Lambda-orange.svg)](https://aws.amazon.com/lambda/)
[![Code Style: Professional](https://img.shields.io/badge/code%20style-professional-brightgreen.svg)](https://github.com/psf/black)

Un servicio unificado y optimizado para obtener estructuras de archivos y descargar contenido desde múltiples sistemas de control de versiones. Diseñado específicamente para AWS Lambda con arquitectura modular enterprise-grade.

## 📋 Tabla de Contenidos

- [Características](#-características)
- [Arquitectura](#-arquitectura)
- [Proveedores Soportados](#-proveedores-soportados)
- [Instalación Local](#-instalación-local)
- [Configuración](#-configuración)
- [Uso Local](#-uso-local)
- [Deployment AWS Lambda](#-deployment-aws-lambda)
- [API Reference](#-api-reference)
- [Ejemplos](#-ejemplos)
- [Monitoreo](#-monitoreo)
- [Troubleshooting](#-troubleshooting)
- [Contribución](#-contribución)

## ✨ Características

### 🎯 Funcionalidades Core
- **Servicio Unificado**: API consistente para múltiples proveedores VCS
- **Dual Operation**: `GET_STRUCTURE` (estructura jerárquica) + `DOWNLOAD_FILE` (descarga de archivos)
- **Multi-Format Output**: JSON estructurado + Markdown optimizado para IA
- **Binary File Support**: Descarga segura de archivos binarios con Base64 encoding

### 🏗️ Arquitectura Enterprise
- **Modular Design**: Arquitectura SOLID con separation of concerns
- **Security First**: Defense-in-depth con validación multicapa
- **AWS Lambda Optimized**: Cold start < 1s, memory efficient
- **Observability**: Structured logging + business metrics automáticas

### 🔒 Seguridad Robusta
- **Path Traversal Protection**: Detección avanzada de ataques
- **Input Sanitization**: Validación exhaustiva de entrada
- **File Size Limits**: Prevención automática de DoS
- **Audit Trail**: Logging completo para compliance

## 🏗️ Arquitectura

```
source_code_lambda/
├── lambda_handler.py          # 🎯 Entry point AWS Lambda (28 líneas)
├── main.py                    # 🧪 Local testing (18 líneas)
├── requirements.txt           # 📦 Dependencias optimizadas
├── .gitignore                # 🛡️ Seguridad de repositorio
├── README.md                 # 📚 Esta documentación
└── app/                      # 🏗️ Arquitectura modular
    ├── core/                 # 🔧 Componentes fundamentales
    │   ├── constants.py      # ⚙️ Configuración centralizada
    │   ├── exceptions.py     # 🚨 Manejo de errores tipado
    │   ├── logger.py         # 📊 Sistema de logging optimizado
    │   └── validators.py     # 🛡️ Validación robusta
    ├── utils/               # 🔧 Utilidades HTTP
    │   ├── request_parser.py # 📥 Parsing inteligente de eventos
    │   └── http_responses.py # 📤 Respuestas HTTP estandarizadas
    ├── handlers/            # 🎯 Lógica de negocio
    │   ├── structure_handler.py # 📁 Manejo GET_STRUCTURE
    │   └── download_handler.py  # 📥 Manejo DOWNLOAD_FILE
    ├── factory/             # 🏭 Factory pattern
    │   └── source_code_factory.py # 🔨 Creación de managers
    ├── services/            # 🔧 Servicios de dominio
    │   └── structure_formatter.py # 📝 Formateo Markdown
    └── managers/            # 🔗 Integraciones VCS
        ├── github_manager.py    # 🐙 GitHub API integration
        ├── gitlab_manager.py    # 🦊 GitLab API integration
        ├── azure_manager.py     # ☁️ Azure DevOps integration
        └── svn_manager.py       # 📚 SVN integration (local only)
```

## 🔗 Proveedores Soportados

| Proveedor | AWS Lambda | Local | Autenticación | Notas |
|-----------|------------|-------|---------------|-------|
| **GitHub** | ✅ | ✅ | Personal Access Token | Recomendado para Lambda |
| **GitLab** | ✅ | ✅ | Private Token | Soporta GitLab.com + self-hosted |
| **Azure DevOps** | ✅ | ✅ | Personal Access Token | Git repositories |
| **Subversion (SVN)** | ❌ | ✅ | Username/Password | Solo entornos locales |

> **💡 Nota**: SVN no funciona en AWS Lambda debido a limitaciones de subprocess y binarios del sistema.

## 🚀 Instalación Local

### Prerequisitos

- **Python 3.9+** (Recomendado: 3.9 para compatibilidad con Lambda)
- **pip** package manager
- **Git** (opcional, para clonar repositorio)

### 1. Clonar Repositorio

```bash
# Clonar el repositorio
git clone https://github.com/tu-usuario/source-code-lambda.git
cd source-code-lambda

# O crear directorio y copiar archivos
mkdir source-code-lambda
cd source-code-lambda
```

### 2. Crear Entorno Virtual

```bash
# Crear entorno virtual
python -m venv venv

# Activar entorno virtual
# En Linux/macOS:
source venv/bin/activate
# En Windows:
venv\Scripts\activate
```

### 3. Instalar Dependencias

```bash
# Instalar dependencias
pip install -r requirements.txt

# Verificar instalación
pip list
```

### 4. Verificar Instalación

```bash
# Test básico
python -c "from app.core.logger import get_logger; print('✅ Instalación correcta')"
```

## ⚙️ Configuración

### Variables de Entorno (Opcional)

```bash
# Crear archivo .env (opcional)
cat > .env << EOF
# Configuración opcional del sistema
MAX_FILE_SIZE_MB=10
REQUEST_TIMEOUT=30
LOG_LEVEL=INFO
ENABLE_DEBUG_METRICS=false
EOF
```

### Tokens de Acceso

#### GitHub Personal Access Token
1. Ve a **GitHub Settings** → **Developer settings** → **Personal access tokens**
2. Genera token con permisos: `repo` (para repositorios privados) o `public_repo`
3. Copia el token: `ghp_xxxxxxxxxxxxxxxxxxxx`

#### GitLab Private Token
1. Ve a **GitLab Profile** → **Access Tokens**
2. Crea token con scope: `read_repository`
3. Copia el token: `glpat-xxxxxxxxxxxxxxxxxxxx`

#### Azure DevOps PAT
1. Ve a **Azure DevOps** → **User Settings** → **Personal Access Tokens**
2. Crea token con scope: `Code (read)`
3. Copia el token (base64 encoded)

## 🧪 Uso Local

### Método 1: Archivo de Configuración

#### 1. Crear Evento de Prueba

```bash
# Crear directorio para eventos
mkdir test_events

# GET_STRUCTURE para GitHub
cat > test_events/github_structure.json << EOF
{
  "operation": "GET_STRUCTURE",
  "provider": "github",
  "config": {
    "token": "ghp_tu_token_aqui",
    "owner": "octocat",
    "repo": "Hello-World",
    "branch": "main"
  }
}
EOF

# DOWNLOAD_FILE para GitHub
cat > test_events/github_download.json << EOF
{
  "operation": "DOWNLOAD_FILE",
  "provider": "github",
  "config": {
    "token": "ghp_tu_token_aqui",
    "owner": "octocat",
    "repo": "Hello-World",
    "branch": "main"
  },
  "path": "README"
}
EOF
```

#### 2. Ejecutar Tests

```bash
# Test GET_STRUCTURE
python main.py test_events/github_structure.json

# Test DOWNLOAD_FILE
python main.py test_events/github_download.json
```

### Método 2: Argumentos CLI

```bash
# GET_STRUCTURE via CLI
python main.py \
  --operation GET_STRUCTURE \
  --provider github \
  --config '{"token":"ghp_tu_token","owner":"octocat","repo":"Hello-World"}'

# DOWNLOAD_FILE via CLI
python main.py \
  --operation DOWNLOAD_FILE \
  --provider github \
  --config '{"token":"ghp_tu_token","owner":"octocat","repo":"Hello-World"}' \
  --path README
```

### Ejemplos por Proveedor

#### GitLab
```json
{
  "operation": "GET_STRUCTURE",
  "provider": "gitlab",
  "config": {
    "token": "glpat_tu_token_aqui",
    "project_path": "gitlab-org/gitlab",
    "branch": "main",
    "base_url": "https://gitlab.com"
  }
}
```

#### Azure DevOps
```json
{
  "operation": "GET_STRUCTURE", 
  "provider": "azure",
  "config": {
    "token": "tu_azure_pat",
    "organization": "tu-org",
    "project": "tu-proyecto",
    "repository": "tu-repo",
    "branch": "refs/heads/main"
  }
}
```

#### SVN (Solo Local)
```json
{
  "operation": "GET_STRUCTURE",
  "provider": "svn",
  "config": {
    "repo_url": "https://svn.apache.org/repos/asf/httpd/httpd/trunk",
    "username": "tu_usuario",
    "password": "tu_password"
  }
}
```

## 🚀 Deployment AWS Lambda

### Prerequisitos AWS

- **AWS CLI** configurado con credenciales apropiadas
- **Permisos IAM** para crear/actualizar Lambda functions
- **Python 3.9** runtime environment

### Método 1: AWS CLI (Recomendado)

#### 1. Crear Package de Deployment

```bash
# Crear directorio temporal
mkdir lambda_package
cd lambda_package

# Copiar código fuente
cp -r ../app .
cp ../lambda_handler.py .
cp ../requirements.txt .

# Instalar dependencias en el package
pip install -r requirements.txt -t .

# Crear ZIP optimizado
zip -r ../source_code_lambda.zip . \
  -x "*.pyc" "__pycache__/*" "*.git*" "test_*" "*.DS_Store"

cd ..
rm -rf lambda_package
```

#### 2. Crear Función Lambda

```bash
# Crear función Lambda
aws lambda create-function \
  --function-name source-code-manager \
  --runtime python3.9 \
  --role arn:aws:iam::TU_ACCOUNT_ID:role/lambda-execution-role \
  --handler lambda_handler.lambda_handler \
  --zip-file fileb://source_code_lambda.zip \
  --timeout 30 \
  --memory-size 512 \
  --environment Variables='{
    "MAX_FILE_SIZE_MB":"10",
    "REQUEST_TIMEOUT":"25",
    "LOG_LEVEL":"INFO"
  }'
```

#### 3. Actualizar Función (Deploy Updates)

```bash
# Actualizar código
aws lambda update-function-code \
  --function-name source-code-manager \
  --zip-file fileb://source_code_lambda.zip

# Actualizar configuración
aws lambda update-function-configuration \
  --function-name source-code-manager \
  --timeout 30 \
  --memory-size 512 \
  --environment Variables='{
    "MAX_FILE_SIZE_MB":"10",
    "REQUEST_TIMEOUT":"25", 
    "LOG_LEVEL":"INFO"
  }'
```

### Método 2: CloudFormation

#### 1. Crear Template CloudFormation

```yaml
# cloudformation-template.yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Source Code Repository Manager Lambda'

Parameters:
  FunctionName:
    Type: String
    Default: source-code-manager
    Description: Name of the Lambda function

Resources:
  LambdaExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
      Policies:
        - PolicyName: CloudWatchLogs
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: !Sub 'arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/${FunctionName}:*'

  SourceCodeLambda:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Ref FunctionName
      Runtime: python3.9
      Handler: lambda_handler.lambda_handler
      Role: !GetAtt LambdaExecutionRole.Arn
      Code:
        ZipFile: |
          # Placeholder - replace with actual deployment package
          def lambda_handler(event, context):
              return {"statusCode": 200, "body": "Deploy real code"}
      Timeout: 30
      MemorySize: 512
      Environment:
        Variables:
          MAX_FILE_SIZE_MB: "10"
          REQUEST_TIMEOUT: "25"
          LOG_LEVEL: "INFO"

  ApiGateway:
    Type: AWS::ApiGateway::RestApi
    Properties:
      Name: !Sub '${FunctionName}-api'
      Description: 'API for Source Code Repository Manager'

  ApiGatewayResource:
    Type: AWS::ApiGateway::Resource
    Properties:
      RestApiId: !Ref ApiGateway
      ParentId: !GetAtt ApiGateway.RootResourceId
      PathPart: 'source-code'

  ApiGatewayMethod:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref ApiGateway
      ResourceId: !Ref ApiGatewayResource
      HttpMethod: POST
      AuthorizationType: NONE
      Integration:
        Type: AWS_PROXY
        IntegrationHttpMethod: POST
        Uri: !Sub 'arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${SourceCodeLambda.Arn}/invocations'

  LambdaInvokePermission:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: !Ref SourceCodeLambda
      Principal: apigateway.amazonaws.com
      SourceArn: !Sub 'arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${ApiGateway}/*/*'

Outputs:
  LambdaFunctionArn:
    Description: 'Lambda Function ARN'
    Value: !GetAtt SourceCodeLambda.Arn
    
  ApiGatewayUrl:
    Description: 'API Gateway URL'
    Value: !Sub 'https://${ApiGateway}.execute-api.${AWS::Region}.amazonaws.com/prod/source-code'
```

#### 2. Deploy con CloudFormation

```bash
# Deploy stack
aws cloudformation deploy \
  --template-file cloudformation-template.yaml \
  --stack-name source-code-manager-stack \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides FunctionName=source-code-manager

# Actualizar código después de crear stack
aws lambda update-function-code \
  --function-name source-code-manager \
  --zip-file fileb://source_code_lambda.zip
```

### Método 3: Serverless Framework

#### 1. Instalar Serverless

```bash
# Instalar Serverless Framework
npm install -g serverless

# Crear serverless.yml
cat > serverless.yml << EOF
service: source-code-manager

provider:
  name: aws
  runtime: python3.9
  timeout: 30
  memorySize: 512
  environment:
    MAX_FILE_SIZE_MB: 10
    REQUEST_TIMEOUT: 25
    LOG_LEVEL: INFO

functions:
  sourceCodeManager:
    handler: lambda_handler.lambda_handler
    events:
      - http:
          path: source-code
          method: post
          cors: true

plugins:
  - serverless-python-requirements

custom:
  pythonRequirements:
    dockerizePip: false
    slim: true
EOF
```

#### 2. Deploy con Serverless

```bash
# Deploy
serverless deploy

# Logs en tiempo real
serverless logs -f sourceCodeManager -t
```

### Testing en AWS Lambda

```bash
# Test directo con AWS CLI
aws lambda invoke \
  --function-name source-code-manager \
  --payload '{
    "body": "{
      \"operation\": \"GET_STRUCTURE\",
      \"provider\": \"github\",
      \"config\": {
        \"token\": \"ghp_tu_token\",
        \"owner\": \"octocat\",
        \"repo\": \"Hello-World\"
      }
    }"
  }' \
  response.json

# Ver respuesta
cat response.json | jq .
```

## 📚 API Reference

### Request Format

#### Lambda Direct Invocation
```json
{
  "body": {
    "operation": "GET_STRUCTURE | DOWNLOAD_FILE",
    "provider": "github | gitlab | azure | svn",
    "config": {
      // Provider-specific configuration
    },
    "path": "file/path"  // Only for DOWNLOAD_FILE
  }
}
```

#### API Gateway Format
```json
{
  "body": "{\"operation\":\"GET_STRUCTURE\",\"provider\":\"github\",\"config\":{...}}"
}
```

### Response Formats

#### GET_STRUCTURE Response
```json
{
  "statusCode": 200,
  "headers": {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*"
  },
  "body": {
    "mensaje": "Estructura obtenida exitosamente",
    "proveedor": "github",
    "markdown": "- 📁 src\n  - 📄 main.py",
    "estructura": [
      {
        "name": "src",
        "path": "src",
        "type": "folder",
        "children": [
          {
            "name": "main.py",
            "path": "src/main.py", 
            "type": "file",
            "download_url": "https://raw.githubusercontent.com/..."
          }
        ]
      }
    ],
    "total_nodos": 150,
    "metadatos": {
      "archivos": 120,
      "carpetas": 30,
      "profundidad_maxima": 8,
      "timestamp": "2025-01-15T10:30:00Z"
    },
    "timestamp": "2025-01-15T10:30:00Z",
    "success": true
  }
}
```

#### DOWNLOAD_FILE Response
```json
{
  "statusCode": 200,
  "headers": {
    "Content-Type": "application/octet-stream",
    "Content-Disposition": "attachment; filename=\"README.md\"",
    "Access-Control-Allow-Origin": "*"
  },
  "body": "IyBIZWxsbyBXb3JsZAoKVGhpcyBpcyBhIHNhbXBsZSBSRUFETUUgZmlsZS4=",
  "isBase64Encoded": true
}
```

#### Error Response
```json
{
  "statusCode": 400,
  "headers": {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*"
  },
  "body": {
    "error": "Falta el campo 'operation'",
    "error_type": "validation_error",
    "error_code": "MISSING_OPERATION",
    "timestamp": "2025-01-15T10:30:00Z",
    "success": false
  }
}
```

### Provider Configuration

#### GitHub
```json
{
  "token": "ghp_xxxxxxxxxxxxxxxxxxxx",
  "owner": "username_or_organization",
  "repo": "repository_name",
  "branch": "main"  // Optional, defaults to "main"
}
```

#### GitLab
```json
{
  "token": "glpat_xxxxxxxxxxxxxxxxxxxx",
  "project_path": "group/project",
  "branch": "main",  // Optional, defaults to "main"
  "base_url": "https://gitlab.com"  // Optional, defaults to gitlab.com
}
```

#### Azure DevOps
```json
{
  "token": "your_azure_pat",
  "organization": "your_organization",
  "project": "your_project", 
  "repository": "your_repository",
  "branch": "refs/heads/main"  // Optional, defaults to "refs/heads/main"
}
```

#### SVN (Local Only)
```json
{
  "repo_url": "https://svn.example.com/repo",
  "username": "your_username",  // Optional
  "password": "your_password"   // Optional
}
```

## 📊 Monitoreo

### CloudWatch Logs

```bash
# Ver logs en tiempo real
aws logs tail /aws/lambda/source-code-manager --follow

# Buscar errores específicos
aws logs filter-log-events \
  --log-group-name /aws/lambda/source-code-manager \
  --filter-pattern "ERROR"

# Métricas de performance
aws logs filter-log-events \
  --log-group-name /aws/lambda/source-code-manager \
  --filter-pattern "PERF_SUCCESS"
```

### Custom Metrics

El sistema automáticamente envía métricas a CloudWatch:

- `structures_retrieved` - Estructuras obtenidas exitosamente
- `files_downloaded` - Archivos descargados
- `request_duration` - Duración de requests
- `response_size` - Tamaño de respuestas
- `errors_*` - Errores categorizados por tipo

### Health Check

```bash
# Health check básico
curl -X POST https://your-api-gateway-url/source-code \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "GET_STRUCTURE",
    "provider": "github",
    "config": {
      "token": "your_token",
      "owner": "octocat",
      "repo": "Hello-World"
    }
  }'
```

## 🔧 Troubleshooting

### Problemas Comunes

#### 1. Error de Imports
```bash
# Síntoma
ModuleNotFoundError: No module named 'app'

# Solución
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
python main.py test_events/github_structure.json
```

#### 2. Error de Token GitHub
```bash
# Síntoma
HTTP 401: Bad credentials

# Verificar token
curl -H "Authorization: token your_token" https://api.github.com/user

# Generar nuevo token con permisos correctos
```

#### 3. Lambda Timeout
```bash
# Síntoma
Task timed out after 30.00 seconds

# Aumentar timeout
aws lambda update-function-configuration \
  --function-name source-code-manager \
  --timeout 60
```

#### 4. Memory Limit Exceeded
```bash
# Síntoma
Runtime.OutOfMemoryError

# Aumentar memoria
aws lambda update-function-configuration \
  --function-name source-code-manager \
  --memory-size 1024
```

#### 5. SVN en Lambda
```bash
# Síntoma
SVN no está soportado en AWS Lambda

# Solución: Usar proveedores alternativos
# GitHub (recomendado), GitLab, o Azure DevOps
```

### Debug Mode

```bash
# Habilitar logging debug
export LOG_LEVEL=DEBUG
python main.py test_events/github_structure.json

# Ver logs detallados
```

### Performance Issues

```bash
# Analizar cold start
aws logs filter-log-events \
  --log-group-name /aws/lambda/source-code-manager \
  --filter-pattern "PERF_START"

# Analizar memory usage
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name MemoryUtilization \
  --dimensions Name=FunctionName,Value=source-code-manager \
  --start-time 2025-01-15T00:00:00Z \
  --end-time 2025-01-15T23:59:59Z \
  --period 3600 \
  --statistics Average,Maximum
```

## 🤝 Contribución

### Development Setup

```bash
# Fork y clone
git clone https://github.com/your-username/source-code-lambda.git
cd source-code-lambda

# Crear branch para feature
git checkout -b feature/nueva-funcionalidad

# Instalar dependencias de desarrollo
pip install -r requirements-dev.txt

# Configurar pre-commit hooks
pre-commit install
```

### Testing Guidelines

```bash
# Ejecutar tests unitarios
pytest tests/

# Coverage report
pytest --cov=app tests/

# Linting
black app/ tests/
flake8 app/ tests/
mypy app/
```

### Pull Request Process

1. **Fork** el repositorio
2. **Crear branch** para tu feature
3. **Escribir tests** para nueva funcionalidad
4. **Asegurar** que todos los tests pasan
5. **Actualizar** documentación si es necesario
6. **Crear Pull Request** con descripción detallada

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para detalles.

## 🙏 Agradecimientos

- **AWS Lambda Team** por la plataforma serverless
- **GitHub/GitLab/Azure** por sus APIs robustas
- **Python Community** por las librerías utilizadas
- **Contributors** por sus mejoras y sugerencias

## 📞 Soporte

- **Issues**: [GitHub Issues](https://github.com/your-username/source-code-lambda/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-username/source-code-lambda/discussions)
- **Wiki**: [Project Wiki](https://github.com/your-username/source-code-lambda/wiki)

---

**⭐ Si este proyecto te fue útil, considera darle una estrella en GitHub ⭐**

---

*Documentación actualizada: Enero 2025*  
*Versión del proyecto: 2.0.0*  
*AWS Lambda Runtime: Python 3.9*