from core.database import db


async def ingest_result(target_value: str, result: dict) -> None:
    """Translates one provider's OSINTResult into graph nodes and edges."""
    if result.get("status") != "ok":
        return  # never ingest failed or empty results

    module = result.get("source_module", "")
    raw = result.get("raw_data", {})

    # --- CT log sources (crt.sh, CertSpotter): Domain <- Subdomain ---
    if module in ("crt.sh", "CertSpotter"):
        await db.execute_write(
            """
            MERGE (d:Domain {name: $target})
            WITH d
            UNWIND $subdomains AS sub
                MERGE (s:Subdomain {name: sub})
                MERGE (s)-[:SUBDOMAIN_OF]->(d)
            """,
            {"target": target_value, "subdomains": raw.get("subdomains", [])},
        )

    # --- HackerTarget: Subdomain -> IPAddress, the first cross-type edge ---
    elif module == "HackerTarget":
        await db.execute_write(
            """
            MERGE (d:Domain {name: $target})
            WITH d
            UNWIND $hosts AS h
                MERGE (s:Subdomain {name: h.hostname})
                MERGE (s)-[:SUBDOMAIN_OF]->(d)
                MERGE (i:IPAddress {address: h.ip})
                MERGE (s)-[:RESOLVES_TO]->(i)
            """,
            {"target": target_value, "hosts": raw.get("hosts", [])},
        )

    # --- Username Scanner: Username -> Platform ---
    elif module == "Username Scanner":
        pairs = [{"platform": k, "url": v} for k, v in raw.get("profiles", {}).items()]
        await db.execute_write(
            """
            MERGE (u:Username {handle: $target})
            WITH u
            UNWIND $pairs AS pair
                MERGE (p:Platform {name: pair.platform})
                MERGE (u)-[r:HAS_PROFILE]->(p)
                SET r.url = pair.url
            """,
            {"target": target_value, "pairs": pairs},
        )

    # --- IP RDAP: IPAddress with org/country properties ---
    elif module == "IP RDAP":
        await db.execute_write(
            """
            MERGE (i:IPAddress {address: $target})
            SET i.org = $org, i.country = $country
            """,
            {"target": target_value, "org": raw.get("name"), "country": raw.get("country")},
        )

    # --- Gravatar: Email node ---
    elif module == "Gravatar":
        await db.execute_write(
            "MERGE (e:Email {address: $target})",
            {"target": target_value},
        )

    # --- Person: only the Person node. Candidate matches stay OUT of the graph:
    #     they are unverified leads, and the graph must hold facts, not guesses.
    elif module.startswith("Person Recon"):
        await db.execute_write(
            "MERGE (pr:Person {name: $target})",
            {"target": target_value},
        )