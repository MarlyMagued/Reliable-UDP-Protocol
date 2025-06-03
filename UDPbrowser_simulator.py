from flask import Flask
from HTTP_Client import HTTPClient 

app = Flask(__name__)

@app.route('/get-data')
def get_data():
    server_ip = "127.0.0.1"
    server_port = 8080
    
    # Initialize HTTP client
    client = HTTPClient(server_ip, server_port)

    # Send GET request
    request = "GET /test_file.txt HTTP/1.0"
    client.send_request(request)

    # Receive response
    response = client.receive_response()

    # Close connection
    client.close()

    if response is None:
        return "No response received from server.", 500

    # Extract body from response
    try:
        if isinstance(response, bytes):
            response_text = response.decode(errors='replace')
        else:
            response_text = response  # already a string
            body = response_text.split("\r\n\r\n", 1)[-1]
    except Exception as e:
        body = f"Failed to decode response: {e}"

    return body

if __name__ == '__main__':
    app.run(port=8000)


