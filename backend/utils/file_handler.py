import pandas as pd
import json
from io import BytesIO, StringIO
from typing import Tuple

def read_any_log_file(content: bytes, filename: str) -> pd.DataFrame:
    """
    Đọc file log theo phần mở rộng:
      - .csv: csv dạng bảng
      - .json|.ndjson: json records / mảng
      - .txt|.log: mỗi dòng là 1 log (cột message)
    Trả về DataFrame ít nhất có cột 'message' (nếu không phải bảng).
    Nếu là syslog format, sẽ parse thành các fields như hostname, program, message, etc.
    """
    name = (filename or "").lower()
    if name.endswith(".csv"):
        return pd.read_csv(BytesIO(content))
    if name.endswith(".json") or name.endswith(".ndjson"):
        text = content.decode("utf-8", errors="ignore").strip()
        try:
            # JSON mảy
            data = json.loads(text)
            return pd.json_normalize(data)
        except Exception:
            # NDJSON
            rows = [json.loads(line) for line in text.splitlines() if line.strip()]
            return pd.json_normalize(rows)
    if name.endswith(".txt") or name.endswith(".log"):
        # coi như mỗi dòng là một log
        lines = [line.strip() for line in StringIO(content.decode("utf-8", errors="ignore")).read().splitlines() if line.strip()]
        raw_df = pd.DataFrame({"message": lines})
        
        # Try to parse as syslog format
        try:
            from .syslog_parser import parse_syslog_dataframe
            parsed_df = parse_syslog_dataframe(raw_df)
            # Only return parsed if it has more columns than just 'message'
            if len(parsed_df.columns) > 1:
                return parsed_df
            return raw_df
        except Exception as e:
            # Fallback to raw message
            import sys
            print(f"[DEBUG] Syslog parse failed: {e}", file=sys.stderr)
            return raw_df
    # fallback: thử đọc csv
    try:
        return pd.read_csv(BytesIO(content))
    except Exception:
        # nếu vẫn không được, coi như txt
        text = content.decode("utf-8", errors="ignore")
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        raw_df = pd.DataFrame({"message": lines})
        
        # Try to parse as syslog format
        try:
            from .syslog_parser import parse_syslog_dataframe
            parsed_df = parse_syslog_dataframe(raw_df)
            return parsed_df
        except Exception:
            return raw_df