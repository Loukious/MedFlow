from medflow_ti.embeddings import embedding_device

print(f"Embedding device: {embedding_device()}")
try:
    import torch

    print(f"torch: {torch.__version__}")
    print(f"cuda available: {torch.cuda.is_available()}")
    if torch.cuda.is_available():
        print(f"gpu: {torch.cuda.get_device_name(0)}")
except Exception as exc:
    print(f"torch check failed: {exc}")

