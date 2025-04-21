# Use an official lightweight Python image.
# 3.12-slim variant is chosen for a balance between size and utility.
FROM python:3.12-slim-bullseye AS base

# Set environment variables to configure Python and pip.
ENV PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=true \
    PIP_DEFAULT_TIMEOUT=100 \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    QR_CODE_DIR=/myapp/qr_codes

# Set the working directory inside the container
WORKDIR /myapp

# Install system dependencies with proper cleanup to reduce image size
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libpq-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy only the requirements, to cache them in Docker layer
COPY ./requirements.txt /myapp/requirements.txt

# Upgrade pip and install Python dependencies from requirements file
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

# Add a non-root user for security
RUN useradd -m myuser
USER myuser

# Copy the rest of your application's code with appropriate ownership
COPY --chown=myuser:myuser . /myapp

# Create QR code directory with correct permissions
# RUN mkdir -p ${QR_CODE_DIR} && chown -R myuser:myuser ${QR_CODE_DIR}

# Inform Docker that the container listens on the specified port at runtime.
EXPOSE 8000

# Use ENTRYPOINT to specify the executable when the container starts.
ENTRYPOINT ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]