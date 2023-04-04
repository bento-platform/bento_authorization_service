from fastapi import FastAPI


app = FastAPI()


@app.get("/service-info")
async def service_info():
    return {}  # TODO
