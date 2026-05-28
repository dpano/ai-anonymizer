# AI Text & Code Anonymizer

A local, web-based utility designed to protect sensitive information and Personally Identifiable Information (PII) before sending code or text to AI models. This tool ensures that your data remains private while allowing the AI to understand the logic and context through language-agnostic, parseable placeholders.

## Features

- **Robust PII Detection**: Built-in patterns for Emails, Phone Numbers, Credit Cards, SSN, IBAN, UUIDs, IP addresses, Paths, and more.
- **Custom Word Masking**: Define specific project names, brand names, or internal identifiers to be masked.
- **Exclusion/Allow-list**: Prevent specific strings (like `mission_id`) from being masked even if a substring (like `mission`) is in the custom words list.
- **Reversible Anonymization**: Easily de-anonymize AI responses back to their original form using the saved mapping.
- **Project-Based Isolation**: Organize your work into different projects, each with its own isolated mapping, custom words, and exclusions.
- **Multi-Layer Persistence**:
  - **Server-side**: Mappings are saved to `mapping_state.json`.
  - **Client-side**: Custom words and exclusions are saved to browser `localStorage` per project.
- **AI-Friendly Output**: Placeholders are formatted as standard variable names (e.g., `ANON_WORD_1`), making the output parseable by code editors and easily understood by AI models.

## Prerequisites

- Python 3.x
- Flask

## Installation

1. Clone the repository to your local machine.
2. Install the required dependencies:
   ```bash
   pip install flask
   ```

## Usage

1. Start the application:
   ```bash
   python app.py
   ```
2. Open your browser and navigate to `http://127.0.0.1:5000`.
3. **Manage Projects**: Use the sidebar to create or switch between projects (e.g., "SQL", "Personal", "API").
4. **Configure Anonymization**:
   - Paste your sensitive text or code into the **Input** field.
   - Add sensitive words to the **Custom words** list.
   - Add context you want to preserve (like variable names that shouldn't be split) to the **Exclusions** list.
5. **Process**:
   - Click **Anonymize →** to generate the safe version for the AI.
   - Copy the **Output** and use it with your AI assistant.
   - To restore the AI's response, paste it into the **Input** field and click **← Deanonymize**.

## Data Privacy

This is a **local-only** tool. No data is sent to external servers except for what you manually copy and paste into your AI assistant. The mapping between sensitive data and placeholders is stored exclusively on your machine.

## Project Structure

- `app.py`: The main Flask application containing the anonymization logic and UI.
- `mapping_state.json`: Local database storing your project mappings and states.
- `README.md`: Project documentation.
