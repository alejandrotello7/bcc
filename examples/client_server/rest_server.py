from fastapi import FastAPI, HTTPException, Request
import io
import sys

app = FastAPI()

@app.post("/execute-code")
async def execute_code(request: Request):
    try:
        code = await request.json()
        code_str = code.get("code")
        exec(code_str)
        return("Success")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error executing code: {str(e)}")
