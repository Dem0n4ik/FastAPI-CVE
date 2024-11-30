from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from datetime import datetime, timedelta
import json

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

DATA_FILE = "cve_data.json"

def load_data():
    with open(DATA_FILE, "r", encoding="utf-8") as file:
        return json.load(file)

def filter_date(cve_data, days, max_items):
    cut_date = datetime.now() - timedelta(days=days)
    filtered = [
        item for item in cve_data
        if datetime.strptime(item.get("dateAdded", ""), "%Y-%m-%d") >= cut_date
    ][:max_items]
    return filtered

def filter_keyword(cve_data, keyword, max_items):
    filtered = [
        item for item in cve_data
        if keyword.lower() in json.dumps(item).lower()
    ][:max_items]
    return filtered


def filter_known(cve_data, max_items):
    filtered = [
        item for item in cve_data
        if item.get("knownRansomwareCampaignUse", "").lower() == "known"
    ][:max_items]
    return filtered

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/info", response_class=HTMLResponse)
async def info(request: Request):
    return templates.TemplateResponse("info.html", {"request": request})

@app.get("/get/all", response_class=HTMLResponse)
async def get_all(request: Request):
    data = load_data()["vulnerabilities"]
    filtered = filter_date(data, days=5, max_items=40)
    return templates.TemplateResponse("all.html", {"request": request, "cves": filtered})

@app.get("/get/new", response_class=HTMLResponse)
async def get_new(request: Request):
    data = load_data()["vulnerabilities"]
    sorted_data = sorted(data, key=lambda x: x.get("dateAdded", ""), reverse=True)
    return templates.TemplateResponse("new.html", {"request": request, "cves": sorted_data[:10]})

@app.get("/get/known", response_class=HTMLResponse)
async def get_known(request: Request):
    data = load_data()["vulnerabilities"]
    filtered = filter_known(data, max_items=10)
    return templates.TemplateResponse("known.html", {"request": request, "cves": filtered})

@app.get("/get", response_class=HTMLResponse)
async def search_page(request: Request, query: str = None):
    cves = []
    if query:
        data = load_data()["vulnerabilities"]
        cves = filter_keyword(data, keyword=query, max_items=40)
    return templates.TemplateResponse("search.html", {"request": request, "cves": cves})
