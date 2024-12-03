import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.preprocessing import StandardScaler
from collections import Counter, defaultdict
import ipaddress
import numpy as np
import openai
import os

# Função para converter IP de string para int e vice-versa
def ip_to_int(ip):
    if isinstance(ip, str):
        return int(ipaddress.ip_address(ip))
    return ip

def int_to_ip(int_ip):
    try:
        return str(ipaddress.ip_address(int(int_ip)))
    except ValueError:
        return str(int_ip)

# Função para gerar o relatório com o ChatGPT
def generate_report_with_chatgpt(attack_details, api_key):
    client = openai.OpenAI(api_key=api_key)
    prompt = (
        "Você é um assistente especializado em segurança cibernética. Sua tarefa é analisar resumos de incidentes de segurança e gerar um relatório detalhado para uma equipe técnica. "
        "O relatório deve ser claro, objetivo e organizado, com foco em informações relevantes para a análise de incidentes e ações corretivas. "
        "Considere os seguintes aspectos ao elaborar o relatório:\n"
        "- Detalhamento do tipo de ataque e sua frequência.\n"
        "- Principais endereços IP de origem e destino envolvidos.\n"
        "- Protocolos e portas mais utilizadas.\n"
        "- Período em que os ataques ocorreram.\n"
        "- Sugestões de medidas de mitigação.\n\n"
        "Seguem os resumos dos ataques detectados:\n\n"
    )

    for attack, details in attack_details.items():
        prompt += f"{attack} Attack Detected {len(details)} times:\n"
        prompt += f"- Most common source IPs: {Counter([d[0] for d in details]).most_common(3)}\n"
        prompt += f"- Most common destination IPs: {Counter([d[1] for d in details]).most_common(1)}\n"
        prompt += f"- Most common source ports: {Counter([d[2] for d in details]).most_common(3)}\n"
        prompt += f"- Most common destination ports: {Counter([d[3] for d in details]).most_common(1)}\n"
        prompt += f"- Protocols used: {Counter([d[4] for d in details]).most_common()}\n\n"

    # Criação da conclusão de chat com a API OpenAI
    response = client.chat.completions.create(
        model="gpt-4",  # ou outro modelo compatível
        messages=[
            {"role": "system", "content": "You are a cybersecurity analyst."},
            {"role": "user", "content": prompt}
        ]
    )

    # Extraindo a mensagem gerada pelo assistente
    model_response = response.choices[0].message.content.strip()

    return model_response



# Configuração inicial
api_key = os.getenv("OPENAI_API_KEY")
data = pd.read_csv('Wednesday-workingHours.pcap_ISCX_ajustado.csv')

# Conversão e tratamento de dados
data['Source IP'] = data['Source IP'].apply(ip_to_int).apply(int_to_ip)
data['Destination IP'] = data['Destination IP'].apply(ip_to_int).apply(int_to_ip)
data['Flow Start Time'] = pd.to_datetime(data['Flow Start'], unit='ms', origin='unix')
data['Flow End Time'] = pd.to_datetime(data['Flow End'], unit='ms', origin='unix')

# Preparação de dados para treinamento
training_columns = ['Destination Port', 'Flow Duration_x', 'Total Fwd Packets', 'Total Backward Packets',
                    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
                    'Flow Bytes/s', 'Flow Packets/s', 'Label']
train_data = data[training_columns]
train_data.replace([np.inf, -np.inf], np.nan, inplace=True)
train_data.fillna(train_data.mean(numeric_only=True), inplace=True)

labels = train_data['Label']
features = train_data.drop('Label', axis=1)
scaler = StandardScaler()
features_scaled = scaler.fit_transform(features)

X_train, X_test, y_train, y_test = train_test_split(features_scaled, labels, test_size=0.1, random_state=42)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Avaliação e agregação dos ataques
predictions = model.predict(X_test)
print(classification_report(y_test, predictions))
attack_details = defaultdict(list)

for i, label in enumerate(predictions):
    if label != 'BENIGN':
        row = data.iloc[i]
        attack_details[label].append((row['Source IP'], row['Destination IP'], row['Source Port'], row['Destination Port'], row['Protocol']))

# Geração e impressão do relatório via ChatGPT
report = generate_report_with_chatgpt(attack_details, api_key)
print(report)
