import uvicorn

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", log_config='log_config.yml', reload=True)
