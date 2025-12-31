# Deployment Guide

## Docker
docker compose up -d

## Heroku
heroku create
heroku config:set SECRET_KEY=...
git push heroku main

## PythonAnywhere / cPanel
- Create virtualenv
- Install requirements
- Set WSGI to project/wsgi.py

## AWS / DigitalOcean / Render
- Use Dockerfile
- Set env vars
