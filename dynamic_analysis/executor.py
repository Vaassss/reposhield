import subprocess

def execute_file(file_path):
    try:
        result = subprocess.run(
            ["python3", file_path],
            capture_output=True,
            timeout=5
        )
        return {
            "success": True,
            "stdout": result.stdout.decode(errors="ignore"),
            "stderr": result.stderr.decode(errors="ignore"),
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}
