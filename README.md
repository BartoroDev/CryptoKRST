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


Technoilogia:
hashlib and datetime 
zrobic klase obiektow z polami: "transaction data, the previous block’s hash, the current block’s hash, nonce, and timestamp."
zrobic klase blockchain: [..]

HOW TO USE:
pip install -r requirements.txt

python3 api.py  

http://127.0.0.1:8000/docs - swagger gui to test API

![test socket conn](https://i.imgur.com/LWxQduQ.png)