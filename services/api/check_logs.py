from rag import collection

def main():
    try:
        result = collection.get(ids=None)
        ids = result.get("ids", [])
        print(f"Total logs stored: {len(ids)}")
        for i in range(len(ids)):
            doc = collection.get(ids=[ids[i]])
            print(f"\nLog {i+1}:")
            print("Text:", doc["documents"][0])
            print("Metadata:", doc["metadatas"][0])
    except Exception as e:
        print("Error accessing ChromaDB:", e)

if __name__ == "__main__":
    main()
