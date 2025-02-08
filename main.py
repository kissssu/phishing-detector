#!/usr/bin/python3

from flask import Flask, jsonify, render_template, request, make_response
import subprocess
import sys
import json

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        email_text = request.form.get("email_content", "")
        try:
            process = subprocess.Popen([sys.executable, 'analyzer.py'],
                                       stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,
                                       text=True)
            stdout, stderr = process.communicate(input=email_text)

            if process.returncode!= 0:
                error_message = f"Analyzer script returned an error:\n{stderr}"
                return jsonify({"error": error_message}), 500  # Return JSON error

            try:
                # Attempt to parse stdout as JSON.  This is the crucial change.
                analysis_results = json.loads(stdout)  # Use json.loads()
                return jsonify(analysis_results), 200  # Return JSON if parsing works

            except json.JSONDecodeError as e:  # Handle JSON decode errors
                error_message = f"Invalid JSON returned by analyzer script: {e}\nStdout: {stdout}\nStderr: {stderr}"
                print(error_message) # Print for server debugging
                return jsonify({"error": "Internal server error: Invalid response from analyzer."}), 500  # Return JSON error

        except FileNotFoundError:
            return jsonify({"error": "Analyzer script not found."}), 500
        except Exception as e:
            error_message = f"An error occurred: {e}"
            print(error_message) # Print for server debugging
            return jsonify({"error": str(e)}), 500

    return render_template("index.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)