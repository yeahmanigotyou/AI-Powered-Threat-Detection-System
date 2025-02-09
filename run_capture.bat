@echo off
REM run_capture.bat
REM This batch file builds the Docker image and runs the container for packet capture.

REM Build the Docker image with tag "tshark-capture"
docker build -t tshark-capture .

REM Run the container:
REM  - --rm: Remove the container after it exits.
REM  - --network=host: (Note: On Docker Desktop for Windows with Linux containers, host networking is limited.)
REM  - --privileged: Required for packet capture.
REM  - -v: Mount the local "data" folder into /data in the container.
docker run --rm --network=host --privileged -v %cd%\data:/data tshark-capture

pause
