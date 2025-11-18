# Maratona Tech

Plataforma web para gestão de eventos de pitch, permitindo cadastro de eventos, pitchs, usuários participantes e votação online. O objetivo é oferecer um ambiente seguro, simples e escalável para competições, hackathons e maratonas de tecnologia.

## 💻 Tecnologias Utilizadas
- Python 3.11+
- Django 5+
- Django REST Framework
- PostgreSQL
- HTML
- CSS
- JavaScript
- Bootstrap
- Gunicorn + Nginx (deploy)
- Docker (ambiente e deploy)
- Swagger/OpenAPI (documentação de API)

## 🚀 Funcionalidades
- Cadastro e autenticação de usuários (admin, jurado, votante);
- Criação e gestão de eventos;
- Cadastro de pitchs vinculados a eventos;
- Votação popular (1 voto por usuário por evento);
- Avaliação técnica por jurados (notas e critérios);
- Rankings: Popular, Técnico e Combinado;
- Painel administrativo customizado;
- Página inicial personalizável;
- Logs e auditoria de votos e avaliações;



## 📦 Instalação e Setup Local
1. Clone o repositório:
	```bash
	git clone https://github.com/SEU_USUARIO/SEU_REPO.git
	cd SEU_REPO
	```
2. Crie e ative um ambiente virtual:
	```bash
	python -m venv .venv
	.venv\Scripts\activate
	```
3. Instale as dependências:
	```bash
	pip install -r requirements.txt
	```
4. Configure as variáveis de ambiente (exemplo em `.env.example`).
5. Execute as migrações:
	```bash
	python manage.py migrate
	```
6. Crie um superusuário:
	```bash
	python manage.py createsuperuser
	```
7. Rode o servidor:
	```bash
	python manage.py runserver
	```

## 🧪 Testes
Execute os testes unitários e de integração:
```bash
python manage.py test
```


## 🔐 Segurança
- Senhas com hashing seguro (PBKDF2 ou Argon2)
- Proteção CSRF, XSS, SQL Injection
- Rate limiting e autenticação JWT
- Logs de auditoria e consentimento LGPD



## 📄 Licença
[MIT](LICENSE)

---

> Para detalhes completos de requisitos, regras de negócio e exemplos de código, consulte o arquivo `docs/requisitos.md`.
