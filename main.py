import uvicorn

if __name__ == "__main__":
    uvicorn.run("app.app:app", host="0.0.0.0", log_config='log_config.yml', log_level="info", reload=True)
