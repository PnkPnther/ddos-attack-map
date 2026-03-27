# ddos-attack-map
Train model: python scripts/train_model.py

Start docker: docker compose up -d

Start producer: python scripts/kafka_producer.py

Start consumer: python scripts/kafka_consumer.py

DISCLAIMER: MAKE SURE TO SWITCH YOUR INTERFACE IN kafka_producer.py TO "lo" BEFORE TESTING, OR ELSE YOUR SYSTEM WILL BE AT RISK OF BEING FLAGGED AS UNDER/LAUNCHING A DDOS ATTACK
Test: sudo tcpreplay -i lo -K <.pcap>
