from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy import select, text

from src.database.connect_db import AsyncDBSession, get_session
from src.routes import auth, contacts


app = FastAPI()

app.include_router(auth.router, prefix="/api")
app.include_router(contacts.router, prefix="/api")


@app.get("/")
async def read_root():
    return {"message": "Contacts API"}


@app.get("/api/healthchecker")
async def healthchecker(session: AsyncDBSession = Depends(get_session)):
    try:
        # Make request
        stmt = select(text("1"))
        result = await session.execute(stmt)
        result = result.scalar()
        if result is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Database is not configured correctly",
            )
        return {"message": "OK"}
    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error connecting to the database",
        )