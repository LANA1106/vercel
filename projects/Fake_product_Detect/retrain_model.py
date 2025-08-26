import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import numpy as np
from app import extract_url_features
import sys
import os
import csv
import json

def load_data_from_file(file_path):
    data = []
    if file_path.endswith('.csv'):
        with open(file_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                # Ensure required fields exist
                if all(k in row for k in ['name', 'description', 'url', 'label']):
                    data.append({
                        'name': row['name'],
                        'description': row['description'],
                        'url': row['url'],
                        'label': int(row['label'])
                    })
    elif file_path.endswith('.json'):
        with open(file_path, encoding='utf-8') as jsonfile:
            items = json.load(jsonfile)
            for row in items:
                if all(k in row for k in ['name', 'description', 'url', 'label']):
                    data.append({
                        'name': row['name'],
                        'description': row['description'],
                        'url': row['url'],
                        'label': int(row['label'])
                    })
    else:
        print('Unsupported file format. Please provide a .csv or .json file.')
        sys.exit(1)
    return data

# Check for user-provided file
if len(sys.argv) > 1:
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        sys.exit(1)
    data = load_data_from_file(file_path)
    print(f"Loaded {len(data)} samples from {file_path}")
else:
    # Example dataset: (Expand this with real data for better results)
    data = [
        # Fake products
        {"name": "cheap rolex watch replica aaa quality", "description": "best copy watch", "url": "http://cheap-rolex-replica.tk", "label": 1},
        {"name": "nike shoes wholesale bulk price factory direct", "description": "knockoff shoes", "url": "http://nike-shoes-bulk.ml", "label": 1},
        {"name": "gucci bag copy 1:1 quality mirror", "description": "mirror quality bag", "url": "http://guccibag-copy.ga", "label": 1},
        {"name": "apple iphone fake super quality chinese", "description": "super fake iphone", "url": "http://apple-iphone-fake.cf", "label": 1},
        {"name": "adidas sneakers replica best price", "description": "top quality fake sneakers", "url": "http://adidas-replica.biz", "label": 1},
        {"name": "prada sunglasses cheap knockoff", "description": "replica sunglasses", "url": "http://prada-sunglasses-fake.com", "label": 1},
        {"name": "louis vuitton bag mirror copy", "description": "high quality fake bag", "url": "http://lv-bag-mirror.net", "label": 1},
        {"name": "rayban shades duplicate offer", "description": "fake rayban shades", "url": "http://rayban-duplicate.org", "label": 1},
        {"name": "puma shoes imitation sale", "description": "imitation puma shoes", "url": "http://puma-imitation.info", "label": 1},
        {"name": "omega watch superclone", "description": "superclone omega watch", "url": "http://omega-superclone.co", "label": 1},
        {"name": "hermes belt fake leather", "description": "fake hermes belt", "url": "http://hermes-belt-fake.com", "label": 1},
        {"name": "cartier bracelet replica", "description": "replica cartier bracelet", "url": "http://cartier-replica.store", "label": 1},
        {"name": "supreme hoodie knockoff", "description": "knockoff supreme hoodie", "url": "http://supreme-knockoff.shop", "label": 1},
        {"name": "balenciaga shoes fake", "description": "fake balenciaga shoes", "url": "http://balenciaga-fake.xyz", "label": 1},
        {"name": "tiffany necklace imitation", "description": "imitation tiffany necklace", "url": "http://tiffany-imitation.com", "label": 1},
        {"name": "versace shirt copy", "description": "copy versace shirt", "url": "http://versace-copy.net", "label": 1},
        {"name": "michael kors bag replica", "description": "replica michael kors bag", "url": "http://mk-replica.org", "label": 1},
        {"name": "tommy hilfiger t-shirt fake", "description": "fake tommy t-shirt", "url": "http://tommy-fake.com", "label": 1},
        {"name": "burberry scarf knockoff", "description": "knockoff burberry scarf", "url": "http://burberry-knockoff.biz", "label": 1},
        {"name": "fossil watch duplicate", "description": "duplicate fossil watch", "url": "http://fossil-duplicate.info", "label": 1},
        {"name": "chanel perfume imitation", "description": "imitation chanel perfume", "url": "http://chanel-imitation.co", "label": 1},
        {"name": "dior bag fake", "description": "fake dior bag", "url": "http://dior-fake.store", "label": 1},
        {"name": "calvin klein jeans replica", "description": "replica calvin klein jeans", "url": "http://ck-replica.shop", "label": 1},
        {"name": "lacoste polo shirt copy", "description": "copy lacoste polo", "url": "http://lacoste-copy.xyz", "label": 1},
        {"name": "montblanc pen fake", "description": "fake montblanc pen", "url": "http://montblanc-fake.com", "label": 1},
        {"name": "hublot watch superclone", "description": "superclone hublot watch", "url": "http://hublot-superclone.net", "label": 1},
        {"name": "coach wallet imitation", "description": "imitation coach wallet", "url": "http://coach-imitation.org", "label": 1},
        {"name": "vans shoes knockoff", "description": "knockoff vans shoes", "url": "http://vans-knockoff.com", "label": 1},
        {"name": "panerai watch replica", "description": "replica panerai watch", "url": "http://panerai-replica.biz", "label": 1},
        {"name": "asics sneakers fake", "description": "fake asics sneakers", "url": "http://asics-fake.info", "label": 1},
        {"name": "seiko watch duplicate", "description": "duplicate seiko watch", "url": "http://seiko-duplicate.co", "label": 1},
        {"name": "bose headphones replica", "description": "replica bose headphones", "url": "http://bose-replica.com", "label": 1},
        {"name": "sennheiser earbuds fake", "description": "fake sennheiser earbuds", "url": "http://sennheiser-fake.net", "label": 1},
        {"name": "beats by dre knockoff", "description": "knockoff beats headphones", "url": "http://beats-knockoff.org", "label": 1},
        {"name": "sony playstation imitation", "description": "imitation playstation console", "url": "http://sony-imitation.biz", "label": 1},
        {"name": "canon camera duplicate", "description": "duplicate canon camera", "url": "http://canon-duplicate.info", "label": 1},
        {"name": "nikon dslr fake", "description": "fake nikon dslr", "url": "http://nikon-fake.co", "label": 1},
        {"name": "samsung galaxy clone", "description": "clone samsung galaxy phone", "url": "http://galaxy-clone.store", "label": 1},
        {"name": "oneplus phone supercopy", "description": "supercopy oneplus phone", "url": "http://oneplus-supercopy.shop", "label": 1},
        {"name": "xiaomi mi band replica", "description": "replica mi band", "url": "http://mi-band-replica.xyz", "label": 1},
        {"name": "fitbit tracker imitation", "description": "imitation fitbit tracker", "url": "http://fitbit-imitation.com", "label": 1},
        # Legitimate products
        {"name": "authentic apple iphone official store f-assured", "description": "genuine product", "url": "https://www.apple.com/in/iphone", "label": 0},
        {"name": "genuine nike running shoes authorized dealer flipkart assured", "description": "original shoes", "url": "https://www.nike.com/in/launch", "label": 0},
        {"name": "official samsung galaxy smartphone amazon choice", "description": "certified product", "url": "https://www.samsung.com/in/smartphones/galaxy", "label": 0},
        {"name": "certified rolex timepiece authorized dealer warranty", "description": "rolex watch", "url": "https://www.rolex.com/watches", "label": 0},
        {"name": "original adidas sneakers store", "description": "adidas official product", "url": "https://www.adidas.com/in", "label": 0},
        {"name": "prada sunglasses official retailer", "description": "genuine prada sunglasses", "url": "https://www.prada.com/in/en.html", "label": 0},
        {"name": "louis vuitton bag authentic", "description": "authentic lv bag", "url": "https://in.louisvuitton.com/eng-in/homepage", "label": 0},
        {"name": "rayban shades original", "description": "original rayban shades", "url": "https://www.ray-ban.com/india", "label": 0},
        {"name": "puma shoes official store", "description": "genuine puma shoes", "url": "https://in.puma.com/in/en", "label": 0},
        {"name": "omega watch authorized dealer", "description": "omega official watch", "url": "https://www.omegawatches.com/", "label": 0},
        {"name": "hermes belt original", "description": "authentic hermes belt", "url": "https://www.hermes.com/in/en/", "label": 0},
        {"name": "cartier bracelet genuine", "description": "genuine cartier bracelet", "url": "https://www.cartier.com/en-in/", "label": 0},
        {"name": "supreme hoodie official", "description": "official supreme hoodie", "url": "https://www.supremenewyork.com/", "label": 0},
        {"name": "balenciaga shoes original", "description": "original balenciaga shoes", "url": "https://www.balenciaga.com/en-in", "label": 0},
        {"name": "tiffany necklace authentic", "description": "authentic tiffany necklace", "url": "https://www.tiffany.com/jewelry/", "label": 0},
        {"name": "versace shirt genuine", "description": "genuine versace shirt", "url": "https://www.versace.com/in/en-in/home/", "label": 0},
        {"name": "michael kors bag original", "description": "original michael kors bag", "url": "https://www.michaelkors.global/en_IN", "label": 0},
        {"name": "tommy hilfiger t-shirt authentic", "description": "authentic tommy t-shirt", "url": "https://in.tommy.com/", "label": 0},
        {"name": "burberry scarf genuine", "description": "genuine burberry scarf", "url": "https://in.burberry.com/", "label": 0},
        {"name": "fossil watch original", "description": "original fossil watch", "url": "https://www.fossil.com/en-in/", "label": 0},
        {"name": "chanel perfume authentic", "description": "authentic chanel perfume", "url": "https://www.chanel.com/in/", "label": 0},
        {"name": "dior bag genuine", "description": "genuine dior bag", "url": "https://www.dior.com/en_in", "label": 0},
        {"name": "calvin klein jeans original", "description": "original calvin klein jeans", "url": "https://www.calvinklein.in/", "label": 0},
        {"name": "lacoste polo shirt authentic", "description": "authentic lacoste polo", "url": "https://www.lacoste.in/", "label": 0},
        {"name": "montblanc pen genuine", "description": "genuine montblanc pen", "url": "https://www.montblanc.com/en-in", "label": 0},
        {"name": "hublot watch original", "description": "original hublot watch", "url": "https://www.hublot.com/en-in/", "label": 0},
        {"name": "coach wallet authentic", "description": "authentic coach wallet", "url": "https://india.coach.com/", "label": 0},
        {"name": "vans shoes genuine", "description": "genuine vans shoes", "url": "https://www.vans.co.uk/", "label": 0},
        {"name": "panerai watch official", "description": "official panerai watch", "url": "https://www.panerai.com/in/en/home.html", "label": 0},
        {"name": "asics sneakers original", "description": "original asics sneakers", "url": "https://www.asics.com/in/en-in/", "label": 0},
        {"name": "seiko watch genuine", "description": "genuine seiko watch", "url": "https://www.seikowatches.com/in-en/", "label": 0},
        {"name": "bose headphones official", "description": "official bose headphones", "url": "https://www.bose.com/en_us/index.html", "label": 0},
        {"name": "sennheiser earbuds original", "description": "original sennheiser earbuds", "url": "https://en-in.sennheiser.com/", "label": 0},
        {"name": "beats by dre authentic", "description": "authentic beats headphones", "url": "https://www.beatsbydre.com/in", "label": 0},
        {"name": "sony playstation official", "description": "official playstation console", "url": "https://www.playstation.com/en-in/", "label": 0},
        {"name": "canon camera genuine", "description": "genuine canon camera", "url": "https://in.canon/en/consumer", "label": 0},
        {"name": "nikon dslr original", "description": "original nikon dslr", "url": "https://www.nikon.co.in/en_IN/", "label": 0},
        {"name": "samsung galaxy official", "description": "official samsung galaxy phone", "url": "https://www.samsung.com/in/", "label": 0},
        {"name": "oneplus phone genuine", "description": "genuine oneplus phone", "url": "https://www.oneplus.in/", "label": 0},
        {"name": "xiaomi mi band authentic", "description": "authentic mi band", "url": "https://www.mi.com/in/mi-band/", "label": 0},
        {"name": "fitbit tracker original", "description": "original fitbit tracker", "url": "https://www.fitbit.com/global/in/home", "label": 0},
    ]
    print("No file provided. Using built-in sample data.")

# Feature extraction
X = []
y = []
for item in data:
    text_features = item["name"] + " " + item["description"]
    url_features = extract_url_features(item["url"])
    combined = text_features + " " + " ".join(map(str, url_features))
    X.append(combined)
    y.append(item["label"])

# Split for validation (optional)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)

# Build ensemble model
nb_model = Pipeline([
    ('tfidf', TfidfVectorizer(ngram_range=(1, 3), max_features=2000)),
    ('classifier', MultinomialNB(alpha=0.1))
])
rf_model = Pipeline([
    ('tfidf', TfidfVectorizer(ngram_range=(1, 2), max_features=1500)),
    ('classifier', RandomForestClassifier(n_estimators=100, random_state=42))
])
lr_model = Pipeline([
    ('tfidf', TfidfVectorizer(ngram_range=(1, 2), max_features=1500)),
    ('classifier', LogisticRegression(random_state=42, max_iter=1000))
])
ensemble = VotingClassifier(
    estimators=[
        ('nb', nb_model),
        ('rf', rf_model),
        ('lr', lr_model)
    ],
    voting='soft'
)

# Train
ensemble.fit(X_train, y_train)

# Evaluate (optional)
y_pred = ensemble.predict(X_test)
print("Validation accuracy:", accuracy_score(y_test, y_pred))

# Save model
joblib.dump(ensemble, 'advanced_fake_product_model.pkl')
print("Model retrained and saved as advanced_fake_product_model.pkl") 