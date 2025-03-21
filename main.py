from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Text, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session
from datetime import datetime
from passlib.context import CryptContext
import jwt
import os

# Configuración de la base de datos
DATABASE_URL = "mssql+pyodbc://SaulLuna:" + "12345678" + "@BlockAndRoll.mssql.somee.com/BlockAndRoll?driver=ODBC+Driver+17+for+SQL+Server"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Configuración de seguridad
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"

# Modelos de Base de Datos
class Usuario(Base):
    __tablename__ = "Usuarios"
    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    contraseña = Column(Text, nullable=False)
    fecha_creacion = Column(DateTime, default=datetime.utcnow)
    carpetas = relationship("Carpeta", back_populates="usuario")
    notas = relationship("Nota", back_populates="usuario")
    archivos = relationship("Archivo", back_populates="usuario")

class Categoria(Base):
    __tablename__ = "Categorias"
    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String(50), unique=True, nullable=False)

class Carpeta(Base):
    __tablename__ = "Carpetas"
    id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(Integer, ForeignKey("Usuarios.id"), nullable=False)
    nombre = Column(String(100), nullable=False)
    fecha_creacion = Column(DateTime, default=datetime.utcnow)
    usuario = relationship("Usuario", back_populates="carpetas")
    notas = relationship("Nota", back_populates="carpeta")

class Nota(Base):
    __tablename__ = "Notas"
    id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(Integer, ForeignKey("Usuarios.id"), nullable=False)
    carpeta_id = Column(Integer, ForeignKey("Carpetas.id"), nullable=True)
    categoria_id = Column(Integer, ForeignKey("Categorias.id"), nullable=True)
    titulo = Column(String(200), nullable=False)
    contenido = Column(Text, nullable=False)
    fecha_creacion = Column(DateTime, default=datetime.utcnow)
    usuario = relationship("Usuario", back_populates="notas")
    carpeta = relationship("Carpeta", back_populates="notas")
    archivos = relationship("Archivo", back_populates="nota")

class Archivo(Base):
    __tablename__ = "Archivos"
    id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(Integer, ForeignKey("Usuarios.id"), nullable=False)
    nota_id = Column(Integer, ForeignKey("Notas.id"), nullable=False)
    nombre = Column(String(255), nullable=False)
    ruta = Column(Text, nullable=False)
    fecha_subida = Column(DateTime, default=datetime.utcnow)
    usuario = relationship("Usuario", back_populates="archivos")
    nota = relationship("Nota", back_populates="archivos")

# Crear tablas
Base.metadata.create_all(bind=engine)

# Aplicación FastAPI
app = FastAPI()

# Dependencia de la BD
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Registro de usuario
@app.post("/usuarios/")
def crear_usuario(nombre: str, email: str, contraseña: str, db: Session = Depends(get_db)):
    usuario_existente = db.query(Usuario).filter(Usuario.email == email).first()
    if usuario_existente:
        raise HTTPException(status_code=400, detail="El email ya está registrado")
    hashed_password = pwd_context.hash(contraseña)
    usuario = Usuario(nombre=nombre, email=email, contraseña=hashed_password)
    db.add(usuario)
    db.commit()
    db.refresh(usuario)
    return {"mensaje": "Usuario creado exitosamente"}

# Autenticación
@app.post("/login/")
def login(email: str, contraseña: str, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.email == email).first()
    if not usuario or not pwd_context.verify(contraseña, usuario.contraseña):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    token = jwt.encode({"user_id": usuario.id}, SECRET_KEY, algorithm=ALGORITHM)
    return {"token": token}

# Crear carpeta
@app.post("/carpetas/")
def crear_carpeta(usuario_id: int, nombre: str, db: Session = Depends(get_db)):
    carpeta = Carpeta(usuario_id=usuario_id, nombre=nombre)
    db.add(carpeta)
    db.commit()
    db.refresh(carpeta)
    return carpeta

# Eliminar carpeta
@app.delete("/carpetas/{carpeta_id}")
def eliminar_carpeta(carpeta_id: int, db: Session = Depends(get_db)):
    carpeta = db.query(Carpeta).filter(Carpeta.id == carpeta_id).first()
    if not carpeta:
        raise HTTPException(status_code=404, detail="Carpeta no encontrada")
    db.delete(carpeta)
    db.commit()
    return {"mensaje": "Carpeta eliminada"}

# editar carpeta
@app.put("/carpetas/{carpeta_id}")
def editar_carpeta(carpeta_id: int, nombre: str, db: Session = Depends(get_db)):
    carpeta = db.query(Carpeta).filter(Carpeta.id == carpeta_id).first()
    if not carpeta:
        raise HTTPException(status_code=404, detail="Carpeta no encontrada")
    carpeta.nombre = nombre
    db.commit()
    db.refresh(carpeta)
    return carpeta

# ver carpetas
@app.get("/carpetas/")
def obtener_carpetas(usuario_id: int, db: Session = Depends(get_db)):
    return db.query(Carpeta).filter(Carpeta.usuario_id == usuario_id).all()


# CRUD de Notas
@app.post("/notas/")
def crear_nota(usuario_id: int, titulo: str, contenido: str, carpeta_id: int = None, categoria_id: int = None, db: Session = Depends(get_db)):
    nota = Nota(usuario_id=usuario_id, titulo=titulo, contenido=contenido, carpeta_id=carpeta_id, categoria_id=categoria_id)
    db.add(nota)
    db.commit()
    db.refresh(nota)
    return nota

@app.get("/notas/{nota_id}")
def obtener_nota(nota_id: int, db: Session = Depends(get_db)):
    nota = db.query(Nota).filter(Nota.id == nota_id).first()
    if not nota:
        raise HTTPException(status_code=404, detail="Nota no encontrada")
    return nota

@app.delete("/notas/{nota_id}")
def eliminar_nota(nota_id: int, db: Session = Depends(get_db)):
    nota = db.query(Nota).filter(Nota.id == nota_id).first()
    if not nota:
        raise HTTPException(status_code=404, detail="Nota no encontrada")
    db.delete(nota)
    db.commit()
    return {"mensaje": "Nota eliminada"}

# Subida de archivos
@app.post("/archivos/")
def subir_archivo(usuario_id: int, nota_id: int, file: UploadFile = File(...), db: Session = Depends(get_db)):
    nota = db.query(Nota).filter(Nota.id == nota_id, Nota.usuario_id == usuario_id).first()
    if not nota:
        raise HTTPException(status_code=404, detail="Nota no encontrada o no pertenece al usuario")

    os.makedirs("uploads", exist_ok=True)
    ruta = f"uploads/{file.filename}"
    with open(ruta, "wb") as buffer:
        buffer.write(file.file.read())

    archivo = Archivo(usuario_id=usuario_id, nota_id=nota_id, nombre=file.filename, ruta=ruta)
    db.add(archivo)
    db.commit()
    db.refresh(archivo)
    return {"mensaje": "Archivo subido exitosamente", "ruta": ruta}

# Obtener categorías
@app.get("/categorias/")
def obtener_categorias(db: Session = Depends(get_db)):
    return db.query(Categoria).all()

# Crear categoría
@app.post("/categorias/")
def crear_categoria(nombre: str, db: Session = Depends(get_db)):
    categoria = Categoria(nombre=nombre)
    db.add(categoria)
    db.commit()
    db.refresh(categoria)
    return categoria
# Eliminar categoría
@app.delete("/categorias/{categoria_id}")
def eliminar_categoria(categoria_id: int, db: Session = Depends(get_db)):
    categoria = db.query(Categoria).filter(Categoria.id == categoria_id).first()
    if not categoria:
        raise HTTPException(status_code=404, detail="Categoría no encontrada")
    db.delete(categoria)
    db.commit()
    return {"mensaje": "Categoría eliminada"}

# Editar categoría
@app.put("/categorias/{categoria_id}")
def editar_categoria(categoria_id: int, nombre: str, db: Session = Depends(get_db)):
    categoria = db.query(Categoria).filter(Categoria.id == categoria_id).first()
    if not categoria:
        raise HTTPException(status_code=404, detail="Categoría no encontrada")
    categoria.nombre = nombre
    db.commit()
    db.refresh(categoria)
    return categoria
