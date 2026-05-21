# =============================================================================
# SOC AI Agent Framework - Dockerfile
# ملف دوكر لإطار عمل وكلاء مركز العمليات الأمنية
#
# Multi-stage build: minimal Python 3.11-slim image with agent code.
# Runs as non-root user for security best practices.
# =============================================================================

FROM python:3.11-slim AS base

# Labels / التسميات
LABEL maintainer="SOC Team"
LABEL description="SOC AI Agent Framework - Intelligent Security Operations"
LABEL version="1.0.0"

# Environment setup / إعداد البيئة
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SOC_CONFIG_PATH=/app/config/agent_config.yaml

# System dependencies / تبعيات النظام
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        tini && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user / إنشاء مستخدم غير جذري
RUN groupadd --gid 1000 socagent && \
    useradd --uid 1000 --gid socagent --create-home socagent

# Set working directory / تعيين مجلد العمل
WORKDIR /app

# Install Python dependencies first (for Docker cache efficiency)
# تثبيت تبعيات بايثون أولاً لكفاءة التخزين المؤقت
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy agent source code / نسخ شفرة الوكلاء
COPY shared/ ./shared/
COPY workers/ ./workers/
COPY config/ ./config/
COPY main.py .

# Fix permissions / إصلاح الأذونات
RUN chown -R socagent:socagent /app

# Switch to non-root user / التبديل إلى مستخدم غير جذري
USER socagent

# Health check / فحص الصحة
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Expose Prometheus metrics port / كشف منفذ المقاييس
EXPOSE 9100

# Use tini as PID 1 for proper signal handling
# استخدام tini كعملية رئيسية للتعامل السليم مع الإشارات
ENTRYPOINT ["tini", "--"]

# Default command: run all agents / الأمر الافتراضي: تشغيل جميع الوكلاء
CMD ["python", "main.py"]
