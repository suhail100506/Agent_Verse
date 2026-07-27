import re
import copy
from datetime import datetime
from bson import ObjectId

class InMemoryCollection:
    def __init__(self, name):
        self.name = name
        self.docs = []

    async def create_index(self, keys, **kwargs):
        pass

    async def find_one(self, filter_dict, sort=None):
        matching = self._filter_docs(filter_dict)
        if not matching:
            return None
        if sort:
            key, direction = sort[0]
            matching.sort(key=lambda d: d.get(key, 0), reverse=(direction == -1))
        return copy.deepcopy(matching[0])

    async def insert_one(self, doc):
        doc_copy = copy.deepcopy(doc)
        if "_id" not in doc_copy:
            doc_copy["_id"] = ObjectId()
        self.docs.append(doc_copy)
        class InsertResult:
            def __init__(self, inserted_id):
                self.inserted_id = inserted_id
        return InsertResult(doc_copy["_id"])

    async def update_one(self, filter_dict, update_dict):
        doc = await self.find_one(filter_dict)
        if not doc:
            return
        real_doc = next(d for d in self.docs if d["_id"] == doc["_id"])
        if "$set" in update_dict:
            for k, v in update_dict["$set"].items():
                self._set_nested(real_doc, k, v)

    def find(self, filter_dict=None):
        matching = self._filter_docs(filter_dict or {})
        return InMemoryCursor(matching)

    async def count_documents(self, filter_dict):
        return len(self._filter_docs(filter_dict))

    def _filter_docs(self, filter_dict):
        results = []
        for d in self.docs:
            match = True
            for k, v in filter_dict.items():
                val = self._get_nested(d, k)
                if isinstance(v, dict):
                    if "$in" in v and val not in v["$in"]:
                        match = False
                    if "$regex" in v:
                        pattern = v["$regex"]
                        flags = re.IGNORECASE if v.get("$options") == "i" else 0
                        if not val or not re.search(pattern, str(val), flags):
                            match = False
                elif str(val) != str(v):
                    match = False
            if match:
                results.append(d)
        return results

    def _get_nested(self, doc, key):
        parts = key.split(".")
        curr = doc
        for p in parts:
            if isinstance(curr, dict) and p in curr:
                curr = curr[p]
            else:
                return None
        return curr

    def _set_nested(self, doc, key, val):
        parts = key.split(".")
        curr = doc
        for p in parts[:-1]:
            if p not in curr or not isinstance(curr[p], dict):
                curr[p] = {}
            curr = curr[p]
        curr[parts[-1]] = val

class InMemoryCursor:
    def __init__(self, docs):
        self.docs = copy.deepcopy(docs)

    def sort(self, key, direction=1):
        if isinstance(key, list):
            key, direction = key[0]
        self.docs.sort(key=lambda d: d.get(key, 0), reverse=(direction == -1))
        return self

    def skip(self, n):
        self.docs = self.docs[n:]
        return self

    def limit(self, n):
        self.docs = self.docs[:n]
        return self

    async def to_list(self, length=None):
        if length:
            return self.docs[:length]
        return self.docs

class InMemoryDatabase:
    def __init__(self):
        self.users = InMemoryCollection("users")
        self.certificates = InMemoryCollection("certificates")
        self.verification_records = InMemoryCollection("verification_records")
        self.template_library = InMemoryCollection("template_library")

    def __getitem__(self, name):
        return getattr(self, name, InMemoryCollection(name))
