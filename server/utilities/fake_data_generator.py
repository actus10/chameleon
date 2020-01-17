import json
import random
import string


def gendata():
    data = ["GET",
            "PUT",
            "POST",
            "DELETE",
            "NTP",
            "GET /admin.php HTTP/1.1\n\n",
            "GET /wpadmin HTTP/1.1\n\n",
            "GET /myapp?q=mike'or1=1;",
            "ELHO",
            "aksjdfaskjdfasdf",
            "asdfkjsa9df8sakdjfas",
            "3rfdsfiuiuhqejnrk;kjrnfewe"
            ]
    labels = [["HTTP"], ["HTTP"], ["HTTP"], ["HTTP"], ["NTP"],
              ["PHP"], ["WordPress"], ["SQL-INJECTION"], ["SMTP"], ["BOT"], ["BOT"], ["BOT"]]

    for i in range(0, 100):
        s = ''
        for i in range(0, 20):
            s += random.choice(string.ascii_letters)
        data.append(s)
        labels.append(['BOT'])
        x = "GET /" + s
        data.append(x)
        labels.append(['HTTP'])
        x = "GET /" + s + ".asp/?user=mike'or 1=1;"
        z = "GET /" + s + ".php/?user=" + s + "'or " + s + "=" + s
        data.append(x)
        labels.append(['SQL-INJECTION'])
        data.append(z)
        labels.append(['SQL-INJECTION'])

    d = {}
    d['samples'] = []
    for i in range(0, len(data) - 1):
        d['samples'].append({"payload": data[i], "labels": labels[i]})
    x = json.dumps(d)
    y = x.replace('''{"samples": [''', 'samples=[')
    z = y.replace(''']}''', "]")
    with open('../training/enabled/fake_data.py', 'w') as f:
        f.write(z)


if __name__ == '__main__':
    gendata()
