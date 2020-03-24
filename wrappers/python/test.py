import json
import math
import os
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from time import perf_counter, time

os.environ.setdefault("RUST_LOG", "debug")

from indy_credx_py import (  # noqa: E402
    create_credential,
    create_credential_definition,
    create_credential_offer,
    create_credential_request,
    create_proof,
    create_master_secret,
    create_or_update_revocation_state,
    create_revocation_registry,
    create_schema,
    generate_nonce,
    process_credential,
    # update_revocation_registry,
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

if 0:
    reps = 5
    start = perf_counter()
    for i in range(reps):
        (rev_reg_def, rev_reg, rev_init_delta, rev_key) = create_revocation_registry(
            origin_did, cred_def, "CL_ACCUM", None, 10000, "ISSUANCE_BY_DEFAULT", None
        )
    print("avg duration", (perf_counter() - start) / reps)
    raise SystemExit
else:
    (rev_reg_def, rev_reg, rev_init_delta, rev_key) = create_revocation_registry(
        origin_did, cred_def, "CL_ACCUM", None, 1000, "ISSUANCE_BY_DEFAULT", None
    )
    print(rev_reg_def, rev_reg.to_json(), rev_key.to_json())

cred_offer = create_credential_offer(schema.schema_id, cred_def, cred_def_cp)
print(cred_offer)

master_secret = create_master_secret()
master_secret_id = "default"

(cred_req, cred_req_metadata) = create_credential_request(
    origin_did, cred_def, master_secret, master_secret_id, cred_offer
)
print(cred_req, cred_req_metadata)


def make_cred(rev_idx: int):
    cred_values = json.dumps(
        {
            "one": {"raw": "oneval", "encoded": "1"},
            "two": {"raw": "twoval", "encoded": "2"},
        }
    )

    print("tails", rev_reg_def.tails_location)

    return create_credential(
        cred_def,
        cred_def_pk,
        cred_offer,
        cred_req,
        cred_values,
        rev_reg_def,
        rev_reg,
        rev_key,
        rev_idx,
        rev_reg_def.tails_location,
    )


def make_and_prove_cred():
    cred, upd_rev_reg, delta = make_cred(1)
    cred_revcd = process_credential(
        cred, cred_req_metadata, master_secret, cred_def, rev_reg_def
    )
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

    timestamp = int(time())
    print(cred_revcd.to_json())
    cred_rev_id = 1  # FIXME need accessor

    # generate a delta from the registry (not using ledger)
    # (_, rev_delta) = update_revocation_registry(
    #     rev_reg_def, upd_rev_reg, (), (), rev_reg_def.tails_location
    # )

    rev_states = {
        rev_reg_def.rev_reg_def_id: [
            create_or_update_revocation_state(
                rev_reg_def,
                rev_init_delta,
                cred_rev_id,
                timestamp,
                rev_reg_def.tails_location,
                None,
            )
        ]
    }

    req_creds = json.dumps(
        {
            "self_attested_attributes": {},
            "requested_attributes": {
                "reft": {"cred_id": "test-cred-id", "revealed": True}
            },
            "requested_predicates": {},
        }
    )

    proof = create_proof(
        proof_req, creds, req_creds, master_secret, schemas, cred_defs, rev_states
    )
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
