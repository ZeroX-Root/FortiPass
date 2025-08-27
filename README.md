# Gestor de Contraseñas y Cifrado de Archivos

**Herramienta sencilla en Python para generar, almacenar y usar contraseñas seguras, además de cifrar y descifrar archivos en tu sistema. Ideal para Kali Linux.**

---

## Características

- **Generación de contraseñas seguras:** Crea 20 contraseñas aleatorias y robustas en segundos.
- **Almacenamiento cifrado:** Guarda las contraseñas en un archivo cifrado mediante Fernet y PBKDF2.
- **Cifrado/descifrado de archivos:** Protege cualquier archivo con una contraseña segura.
- **Menú interactivo en consola:** Interfaz simple y colorida para gestionar todas las funciones.
- **Registro de archivos cifrados:** Control centralizado de qué contraseña protege cada archivo.

---

## Requisitos

- Python 3.x
- Librerías:  
  - `cryptography`  
  - `colorama`

Instalación:

1. Clona el repositorio
```bash
git clone https://github.com/ZeroX-Root/FortiPass.git
cd Directorio

```

2. Crea un entorno virtual
```bash

python3 -m venv nombre_del_entorno

```

3. Instala las dependencias
```bash

pip install cryptography colorama


```

4. Ejecuta el programa
```bash

python3 gestor_contraseñas.py

```

---

### Uso

* Sigue el menú principal para generar contraseñas, verlas, cifrar archivos o descifrarlos.
* Elige el número correspondiente en el menú interactivo.
* Los archivos y contraseñas se almacenan automáticamente en la carpeta storage del proyecto.

---

### Estructura de Carpetas y Archivos

| Carpeta/Archivo      | Propósito                                                                |
|----------------------|--------------------------------------------------------------------------|
| `storage/`           | Almacena contraseñas, claves y archivos cifrados                         |
| `passwords.enc`      | Archivo cifrado de contraseñas generadas                                 |
| `key.key`            | Clave secreta utilizada para cifrar el archivo de contraseñas            |
| `file_registry.txt`  | Registro de archivos cifrados y la contraseña asociada                   |

---

### Seguridad

* Todas las contraseñas y archivos protegidos utilizan cifrado Fernet simétrico con derivación de clave PBKDF2HMAC SHA256.
* Se recomienda mantener la carpeta storage segura y realizar copias de respaldo periódicas.

---

### Compatibilidad

* Funciona en Kali Linux, Ubuntu, Debian, y cualquier sistema con Python 3 instalado.

---

Zero-Root