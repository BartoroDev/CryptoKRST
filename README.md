# CryptoKRST
## do przygotowania na 25.10:
Tworzenie tożsamości cyfrowej 
- skrypt do generowania pary kluczy
- ECDSA
Przechowywanie kluczy w cyfrowym portfelu
- szyfrowanie symetryczne
- format pliku w którym będziemy przechowywac private key
- połączenie z node'em w celu zarejestrowania transakcji
- cos co gada do API
Uruchomienie i rejestracja węzła - OD TEGO START.
- udostepnia API
- uruchomienie w trybie --init i --join                         #TODO: add runtime arguments "--init", "--join"
- nasluchuje na api i na socketach do ktorych polaczone sa inne node'y
- broadcastowanie transakcji
Foothold Node-a:
- przesyłanie dummy jsona w trybie broadcast miedzy wszystkimi polaczonymi nodeami - Mateusz
- api do wpisania wartości do dummy jsona. - Macin


Technologia:
hashlib and datetime 
zrobic klase obiektow z polami: "transaction data, the previous block’s hash, the current block’s hash, nonce, and timestamp."
zrobic klase blockchain: [..]

# HOW TO USE:
pip install -r requirements.txt

#### Najpierw musimy uruchomić node w trybie init z uruchomionym api   
python socket_api.py  

#### Później możemy dołączyć do node-a podając port  
python .\socket_api.py --name B --join 53962

http://127.0.0.1:8XXX/docs - swagger gui do test API api będzie na losowym porcie z przedziału 8000-8999

![rest api broadcasting](https://imgur.com/a/TZYuRyK)

### Samo Uruchomienie Node'a:
    python node.py [--name name_val] [--join port_num1 [ port_num2 ...[ port_numN]]]
    ex: python node.py --name A1 --join 11111 22222

Logi servera są zapisywane w pliku  "server_{server_name}_{server_port}.log".

### samo Łączenie się z Node'em:
    python socket_cli.py node_port
    ex: python socket_cli.py 12345
#### wysyłanie broadcastów:
Aby wysłać broadcast, wiadomość należy zacząć od prefixu "b!":

    (11223)C: b!Hello
