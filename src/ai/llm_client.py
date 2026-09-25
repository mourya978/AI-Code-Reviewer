import ollama


MODEL_NAME = "qwen2.5-coder:7b"


def generate_response(prompt):
    """
    Send a prompt to the local Ollama model
    and return the generated response.
    """

    response = ollama.chat(
        model=MODEL_NAME,
        messages=[
            {
                "role": "user",
                "content": prompt,
            }
        ],
    )

    return response["message"]["content"]