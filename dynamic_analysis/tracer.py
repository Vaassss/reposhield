import subprocess
import tempfile


def trace_execution(file_path):
    trace_file = tempfile.NamedTemporaryFile(delete=False)
    trace_path = trace_file.name
    trace_file.close()

    try:
        subprocess.run(
            ["strace", "-f", "-o", trace_path, "python3", file_path],
            timeout=5,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except Exception:
        pass

    return trace_path
