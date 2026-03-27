# ddos-attack-map

Start docker: docker compose up -d

Start producer: python scripts/kafka_producer.py

Start consumer: python scripts/kafka_consumer.py

Test: sudo tcpreplay -i lo -K <.pcap>