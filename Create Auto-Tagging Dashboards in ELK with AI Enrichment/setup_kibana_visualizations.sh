#!/bin/bash

echo "Setting up Kibana visualizations..."

# Wait for Elasticsearch to have data
sleep 30

# Create a simple visualization for traffic types
curl -X POST "localhost:5601/api/saved_objects/visualization" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "AI Traffic Classification",
      "visState": "{\"title\":\"AI Traffic Classification\",\"type\":\"pie\",\"params\":{\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\"},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"ai_classification.keyword\",\"size\":10,\"order\":\"desc\",\"orderBy\":\"1\"}}]}",
      "uiStateJSON": "{}",
      "description": "",
      "version": 1,
      "kibanaSavedObjectMeta": {
        "searchSourceJSON": "{\"index\":\"network-traffic-*\",\"query\":{\"match_all\":{}}}"
      }
    }
  }'

echo "Basic visualizations created. You can now build more complex dashboards in Kibana UI."
