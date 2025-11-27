import json

from datetime import datetime

def jprint(d=None, *argv):
    try:
        if type(d) != dict:
            d = {"message": str(d)}
        if argv:
            if "message" not in d:
                d["message"] = ""
            for a in argv:
                if type(a) == dict:
                    d.update(a)
                else:
                    d["message"] += " " + str(a)
            d["message"] = d["message"].strip()
    except:
        d = {}

    now = datetime.utcnow()
    d = {"_datetime": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), **d}

    print(json.dumps(d, default=str))
