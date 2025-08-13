import asyncio
import time
from asyncua import Client
import logging

logging.basicConfig(level=logging.INFO)
_logger = logging.getLogger(__name__)

async def check_opcua_application_layer(endpoint_url, timeout=8.0):
    try:
        async with Client(endpoint_url, timeout=timeout) as client:
            endpoints = await client.connect_and_get_server_endpoints()
            #await client.disconnect()
            return bool(endpoints)
    except Exception as e:
        _logger.error(f"[Monitor] Error checking OPC UA application layer: {e}")
        return False

def monitor_opcua_server(endpoint_url, interval=10):
    """
    Periodically check if the OPC UA application layer is responsive.
    Prints status every interval seconds.
    """
    _logger.error(f"[Monitor] Starting OPC UA application layer monitor for {endpoint_url}")
    try:
        while True:
            result = asyncio.run(check_opcua_application_layer(endpoint_url))
            status = "responsive" if result else "UNRESPONSIVE"
            _logger.info(f"[Monitor] {time.strftime('%Y-%m-%d %H:%M:%S')} - Application layer is {status}")

            if status == "UNRESPONSIVE":
                _logger.error(f"[Monitor] {time.strftime('%Y-%m-%d %H:%M:%S')} - Application layer is UNRESPONSIVE")

            time.sleep(interval)
    except KeyboardInterrupt:
        _logger.info("[Monitor] Stopped by user.")

if __name__ == "__main__":
    # Example usage: adjust endpoint and interval as needed
    endpoint = "opc.tcp://192.168.159.198:4840"
    monitor_opcua_server(endpoint, interval=10)
