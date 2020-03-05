import json
import math
import os
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from time import perf_counter

os.environ.setdefault("RUST_LOG", "debug")

from indy_credx_py import (  # noqa: E402
    create_credential,
    create_schema,
    create_credential_definition,
    create_credential_offer,
    create_credential_request,
    create_master_secret,
    create_revocation_registry,
    process_credential,
    create_proof,
    generate_nonce,
    verify_proof,
)

origin_did = "55GkHamhTU1ZbTbV2ab9DE"
schema = create_schema(origin_did, "schema_name", "1.0", ["one", "two"])
schema.seq_no = 15
print("schema", schema.schema_id, schema)

(cred_def, cred_def_pk, cred_def_cp) = create_credential_definition(
    origin_did, schema, "CL", None, json.dumps({"support_revocation": True})
)
print("cred def", cred_def)
print("cred def private key", cred_def_pk)
print("cred def correctness proof", cred_def_cp)

(rev_reg_def, rev_reg, rev_key) = create_revocation_registry(
    origin_did, cred_def, "CL_ACCUM", None, 100, "ISSUANCE_BY_DEFAULT"
)
print(rev_reg_def, rev_reg.to_json(), rev_key.to_json())

cred_offer = create_credential_offer(cred_def, cred_def_cp)
print(cred_offer)

master_secret = create_master_secret()
master_secret_id = "default"

(cred_req, cred_req_metadata) = create_credential_request(
    origin_did, cred_def, master_secret, master_secret_id, cred_offer
)
print(cred_req, cred_req_metadata)


def make_cred():
    cred_values = json.dumps(
        {
            "one": {"raw": "oneval", "encoded": "1"},
            "two": {"raw": "twoval", "encoded": "2"},
        }
    )
    return create_credential(cred_def, cred_def_pk, cred_offer, cred_req, cred_values)


def make_and_prove_cred():
    cred = make_cred()
    cred_revcd = process_credential(cred, cred_req_metadata, master_secret, cred_def)
    schemas = {schema.schema_id: schema}
    cred_defs = {cred_def.cred_def_id: cred_def}

    creds = {"test-cred-id": cred_revcd}
    proof_req = json.dumps(
        {
            "name": "proof",
            "version": "1.0",
            "nonce": generate_nonce(),
            "requested_attributes": {"reft": {"name": "one"}},
            "requested_predicates": {},
            "ver": "1.0",
        }
    )
    req_creds = json.dumps(
        {
            "self_attested_attributes": {},
            "requested_attributes": {
                "reft": {"cred_id": "test-cred-id", "revealed": True}
            },
            "requested_predicates": {},
        }
    )
    proof = create_proof(proof_req, creds, req_creds, master_secret, schemas, cred_defs)
    print("proof:", proof)

    print("verified:", verify_proof(proof, proof_req, schemas, cred_defs, dict()))

    return cred


def make_many_creds(cred_count: int):
    workers = 16
    executor = ThreadPoolExecutor(workers)
    start = perf_counter()
    futures = [executor.submit(make_cred) for i in range(min(cred_count, workers))]
    sent = len(futures)
    while futures:
        (done, not_done) = wait(futures, timeout=None, return_when=FIRST_COMPLETED)
        for check in done:
            check.result()
        add = min(cred_count - sent, workers - len(not_done))
        if add:
            futures = list(not_done) + list(
                executor.submit(make_cred) for i in range(add)
            )
            prev = sent
            sent += add
            if math.floor(prev / 100) != math.floor(sent / 100):
                print(sent)
        else:
            futures = not_done
    end = perf_counter()
    print(end - start, "avg:", ((end - start) / cred_count))


make_and_prove_cred()

print("done")


# buffer = indy_credx.create_test_buffer()
# print(buffer)
# mem = memoryview(buffer)
# del buffer
