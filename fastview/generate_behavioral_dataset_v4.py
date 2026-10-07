#!/usr/bin/env python3
"""
APIShield behavioral dataset generator v4

Purpose
-------
Generate controlled crAPI traffic for behavioral anomaly detection.

Important:
- Uses unique users per run, so rerunning does not fail because of duplicate
  phone numbers/emails.
- Keeps attack labels as metadata only; labels are NOT sent to crAPI.
- Never labels a request BOLA unless a foreign object ID is actually known.
- Uses the locally supplied crAPI OpenAPI specification to avoid inventing
  endpoints/methods.
- Produces normal traffic plus deliberately allocated attack episodes.
"""

from __future__ import annotations

import argparse
import json
import random
import string
import time
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import requests


DEFAULT_BASE_URL = "http://localhost:8888"
DEFAULT_SPEC = "targets/crAPI-main/openapi-spec/crapi-openapi-spec.json"
DEFAULT_OUTPUT = "data/behavioral/crapi_behavioral_dataset_v4.jsonl"
RANDOM_SEED = 42


@dataclass
class User:
    user_id: str
    email: str
    password: str
    number: str
    token: str


@dataclass
class Event:
    event_id: str
    timestamp: str
    user_id: str
    session_id: str
    method: str
    path: str
    operation_id: str
    status_code: int
    response_size: int
    query_parameter_count: int
    request_body_size: int
    request_body_fields: list[str]
    object_id: Optional[str]
    object_type: Optional[str]
    scenario: str
    behavior_label: str
    attack_variant: str
    event_index: int


class Generator:
    def __init__(self, base_url: str, spec_path: str, seed: int = RANDOM_SEED):
        self.base_url = base_url.rstrip("/")
        self.rng = random.Random(seed)
        self.session = requests.Session()
        self.events: list[dict[str, Any]] = []
        self.users: list[User] = []
        self.known_objects: dict[str, dict[str, list[str]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self.api = self._load_spec(spec_path)
        self.run_id = uuid.uuid4().hex[:10]
        self.event_index = 0

    def _load_spec(self, path: str) -> dict[str, Any]:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"OpenAPI spec not found: {p}")
        return json.loads(p.read_text(encoding="utf-8"))

    def operation_id(self, method: str, path: str) -> str:
        op = self.api.get("paths", {}).get(path, {}).get(method.lower(), {})
        return op.get("operationId", f"{method.upper()} {path}")

    def has_operation(self, method: str, path: str) -> bool:
        return method.lower() in self.api.get("paths", {}).get(path, {})

    def _unique_identity(self, index: int) -> tuple[str, str]:
        # UUID keeps reruns unique even though traffic randomness remains seeded.
        suffix = f"{self.run_id}_{index:03d}"
        email = f"apishield_{suffix}@example.com"

        # crAPI expects a 10-digit number. Use a deterministic index component
        # plus a per-run component; avoid reusing the previous seeded numbers.
        run_num = int(self.run_id[:8], 16) % 100000
        number = f"{9000000000 + ((run_num * 31 + index) % 999999999):010d}"
        return email, number

    def signup_login(self, index: int) -> Optional[User]:
        email, number = self._unique_identity(index)
        password = f"ApiShield!{self.run_id}_{index:03d}"

        signup_body = {
            "email": email,
            "name": f"APIShield User {index:03d}",
            "number": number,
            "password": password,
        }

        try:
            r = self.session.post(
                f"{self.base_url}/identity/api/auth/signup",
                json=signup_body,
                timeout=15,
            )
        except requests.RequestException as e:
            print(f"    signup request error: {e}")
            return None

        if r.status_code not in (200, 201):
            try:
                body = r.json()
            except Exception:
                body = r.text[:300]
            print(f"    signup failed: HTTP {r.status_code} body={body}")
            return None

        try:
            r = self.session.post(
                f"{self.base_url}/identity/api/auth/login",
                json={"email": email, "password": password},
                timeout=15,
            )
        except requests.RequestException as e:
            print(f"    login request error: {e}")
            return None

        if r.status_code != 200:
            try:
                body = r.json()
            except Exception:
                body = r.text[:300]
            print(f"    login failed: HTTP {r.status_code} body={body}")
            return None

        try:
            data = r.json()
        except Exception:
            print("    login failed: non-JSON response")
            return None

        token = (
            data.get("token")
            or data.get("authentication", {}).get("token")
            or data.get("data", {}).get("token")
        )

        if not token:
            print(f"    login succeeded but no token found: {data}")
            return None

        return User(
            user_id=f"user_{index:03d}",
            email=email,
            password=password,
            number=number,
            token=token,
        )

    def create_users(self, count: int) -> None:
        print(f"Creating {count} users...")
        for i in range(1, count + 1):
            user = self.signup_login(i)
            print(f"  user {i:03d}: token={'yes' if user else 'no'}")
            if user:
                self.users.append(user)

        if not self.users:
            raise RuntimeError(
                "No user could authenticate. crAPI may be unavailable or the "
                "authentication contract may have changed."
            )

        print(f"Authenticated users: {len(self.users)}/{count}")

    def _request(
        self,
        user: User,
        method: str,
        path: str,
        *,
        scenario: str,
        behavior_label: str = "NORMAL",
        attack_variant: str = "none",
        params: Optional[dict[str, Any]] = None,
        json_body: Optional[dict[str, Any]] = None,
        object_id: Optional[str] = None,
        object_type: Optional[str] = None,
        session_id: str,
    ) -> dict[str, Any]:

        url = f"{self.base_url}{path}"
        headers = {"Authorization": f"Bearer {user.token}"}

        try:
            r = self.session.request(
                method.upper(),
                url,
                headers=headers,
                params=params,
                json=json_body,
                timeout=15,
            )
            status = r.status_code
            response_size = len(r.content)
        except requests.RequestException:
            status = 0
            response_size = 0

        fields = list(json_body.keys()) if isinstance(json_body, dict) else []
        request_body_size = len(
            json.dumps(json_body, separators=(",", ":")).encode("utf-8")
        ) if json_body is not None else 0

        event = Event(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            user_id=user.user_id,
            session_id=session_id,
            method=method.upper(),
            path=path,
            operation_id=self.operation_id(method, path),
            status_code=status,
            response_size=response_size,
            query_parameter_count=len(params or {}),
            request_body_size=request_body_size,
            request_body_fields=fields,
            object_id=str(object_id) if object_id is not None else None,
            object_type=object_type,
            scenario=scenario,
            behavior_label=behavior_label,
            attack_variant=attack_variant,
            event_index=self.event_index,
        )
        self.event_index += 1
        self.events.append(asdict(event))

        # Only treat successful object requests as evidence of ownership.
        if (
            status in (200, 201, 204)
            and object_id is not None
            and object_type is not None
        ):
            if str(object_id) not in self.known_objects[user.user_id][object_type]:
                self.known_objects[user.user_id][object_type].append(str(object_id))

        return asdict(event)

    def _sleep(self, low=0.04, high=0.15):
        time.sleep(self.rng.uniform(low, high))

    def normal_episode(self, user: User, session_id: str, count: int = 10):
        candidates = [
            ("GET", "/identity/api/v2/user/dashboard"),
            ("GET", "/identity/api/v2/vehicle/vehicles"),
            ("GET", "/community/api/v2/community/posts/recent"),
            ("GET", "/workshop/api/shop/orders/all"),
        ]

        for _ in range(count):
            method, path = self.rng.choice(candidates)
            if self.has_operation(method, path):
                self._request(
                    user, method, path,
                    scenario="normal",
                    session_id=session_id,
                )
            self._sleep()

    def collect_ownership(self, user: User):
        """
        Discover object IDs from responses where practical.

        The generator intentionally does NOT fabricate object ownership.
        Known object IDs can also be supplied by successful object-level
        operations observed during traffic generation.
        """
        # Dashboard is useful context but does not necessarily expose all
        # collection IDs, so we only use it as normal traffic.
        sid = f"{user.user_id}_ownership"
        self._request(
            user, "GET", "/identity/api/v2/user/dashboard",
            scenario="ownership_discovery",
            session_id=sid,
        )

        # Query collection endpoints and attempt to extract common ID fields.
        collections = [
            ("videos", "GET", "/identity/api/v2/user/videos"),
            ("orders", "GET", "/workshop/api/shop/orders/all"),
            ("vehicles", "GET", "/identity/api/v2/vehicle/vehicles"),
            ("community_posts", "GET", "/community/api/v2/community/posts"),
        ]

        for obj_type, method, path in collections:
            if not self.has_operation(method, path):
                continue

            try:
                r = self.session.get(
                    f"{self.base_url}{path}",
                    headers={"Authorization": f"Bearer {user.token}"},
                    timeout=15,
                )
                if r.status_code != 200:
                    continue
                data = r.json()
            except Exception:
                continue

            ids = self._extract_ids(data)
            for oid in ids[:20]:
                if oid not in self.known_objects[user.user_id][obj_type]:
                    self.known_objects[user.user_id][obj_type].append(oid)

    def _extract_ids(self, value: Any) -> list[str]:
        found: list[str] = []

        def walk(x):
            if isinstance(x, dict):
                for k, v in x.items():
                    if k.lower() in {
                        "id", "video_id", "order_id", "vehicleid",
                        "vehicle_id", "postid", "post_id",
                    } and isinstance(v, (str, int)):
                        found.append(str(v))
                    walk(v)
            elif isinstance(x, list):
                for item in x:
                    walk(item)

        walk(value)
        return list(dict.fromkeys(found))

    def attack_bola(self, attacker: User, victim: User, session_id: str):
        resource = "/identity/api/v2/user/videos/{video_id}"
        if not self.has_operation("GET", resource):
            return 0

        foreign = self.known_objects[victim.user_id]["videos"]
        if not foreign:
            return 0

        ids = foreign[: min(4, len(foreign))]
        for oid in ids:
            self._request(
                attacker, "GET",
                resource.format(video_id=oid),
                scenario="bola",
                behavior_label="BOLA",
                attack_variant="foreign_object_access",
                object_id=oid,
                object_type="videos",
                session_id=session_id,
            )
            self._sleep(0.05, 0.18)
        return len(ids)

    def attack_enumeration(self, user: User, session_id: str):
        """
        Enumeration is generated only on documented object endpoints.
        """
        resource = "/identity/api/v2/user/videos/{video_id}"
        if not self.has_operation("GET", resource):
            return 0

        # IDs are deliberately varied; they are not claimed to be valid.
        start = self.rng.randint(1, 8)
        ids = [str(start + i) for i in range(10)]

        for oid in ids:
            self._request(
                user, "GET",
                resource.format(video_id=oid),
                scenario="enumeration",
                behavior_label="ENUMERATION",
                attack_variant=self.rng.choice(
                    ["sequential", "sparse", "random_walk"]
                ),
                object_id=oid,
                object_type="videos",
                session_id=session_id,
            )
            self._sleep(0.03, 0.09)
        return len(ids)

    def attack_bfla(self, user: User, session_id: str):
        targets = [
            ("GET", "/workshop/api/management/users/all"),
            ("DELETE", "/identity/api/v2/admin/videos/{video_id}"),
        ]

        generated = 0
        for method, path in targets:
            if not self.has_operation(method, path):
                continue

            if "{video_id}" in path:
                oid = str(self.rng.randint(1, 10))
                actual_path = path.format(video_id=oid)
                self._request(
                    user, method, actual_path,
                    scenario="bfla",
                    behavior_label="BFLA",
                    attack_variant="privileged_operation",
                    object_id=oid,
                    object_type="videos",
                    session_id=session_id,
                )
            else:
                self._request(
                    user, method, path,
                    scenario="bfla",
                    behavior_label="BFLA",
                    attack_variant="privileged_operation",
                    session_id=session_id,
                )
            generated += 1
        return generated

    def attack_mass_assignment(self, user: User, session_id: str):
        path = "/identity/api/v2/user/change-email"
        if not self.has_operation("POST", path):
            return 0

        body = {
            "new_email": f"mutated_{self.run_id}_{user.user_id}@example.com",
            "old_email": user.email,
            "role": "ROLE_ADMIN",
            "isAdmin": True,
            "available_credit": 999999,
        }

        self._request(
            user, "POST", path,
            scenario="mass_assignment",
            behavior_label="MASS_ASSIGNMENT",
            attack_variant="unexpected_sensitive_fields",
            json_body=body,
            session_id=session_id,
        )
        return 1

    def attack_flooding(self, user: User, session_id: str):
        targets = [
            "/identity/api/v2/user/dashboard",
            "/identity/api/v2/vehicle/vehicles",
            "/community/api/v2/community/posts/recent",
            "/workshop/api/shop/orders/all",
        ]
        targets = [p for p in targets if self.has_operation("GET", p)]
        if not targets:
            return 0

        count = self.rng.randint(35, 60)
        for _ in range(count):
            path = self.rng.choice(targets)
            self._request(
                user, "GET", path,
                scenario="flooding",
                behavior_label="FLOODING",
                attack_variant=self.rng.choice(
                    ["single_endpoint_burst", "mixed_endpoint_burst"]
                ),
                session_id=session_id,
            )
            time.sleep(self.rng.uniform(0.005, 0.025))
        return count

    def attack_business_flow(self, user: User, session_id: str):
        """
        Exercise documented business-flow endpoints. This is labeled as
        business-flow abuse because the episode is intentionally composed
        around a suspicious sequence; individual HTTP responses are not used
        as the label.
        """
        steps = [
            ("POST", "/workshop/api/shop/orders"),
            ("GET", "/workshop/api/shop/orders/all"),
            ("POST", "/community/api/v2/community/posts"),
        ]

        generated = 0
        for method, path in steps:
            if not self.has_operation(method, path):
                continue

            body = None
            if method == "POST":
                # Keep body minimal here; exact schemas are version-dependent.
                # The event remains useful as a sequence feature even if the
                # application rejects the request.
                body = {}

            self._request(
                user, method, path,
                scenario="business_flow_abuse",
                behavior_label="BUSINESS_FLOW_ABUSE",
                attack_variant="rapid_business_sequence",
                json_body=body,
                session_id=session_id,
            )
            generated += 1
            self._sleep(0.02, 0.06)
        return generated

    def generate(self, users: int):
        self.create_users(users)

        # Ownership discovery first.
        for user in self.users:
            self.collect_ownership(user)
            print(
                f"  ownership {user.user_id}: "
                f"{dict((k, len(v)) for k, v in self.known_objects[user.user_id].items())}"
            )

        # Deliberate balanced allocation. Every authenticated user receives
        # one primary attack; half receive a second attack episode.
        labels = [
            "BOLA",
            "BFLA",
            "MASS_ASSIGNMENT",
            "ENUMERATION",
            "FLOODING",
            "BUSINESS_FLOW_ABUSE",
        ]

        shuffled = self.users[:]
        self.rng.shuffle(shuffled)

        for i, user in enumerate(shuffled):
            session_id = f"{user.user_id}_behavioral"

            # Normal context before attack.
            self.normal_episode(user, session_id, self.rng.randint(5, 10))

            primary = labels[i % len(labels)]

            # BOLA requires a real foreign object. If unavailable, use
            # enumeration so the dataset does not contain fabricated BOLA.
            if primary == "BOLA":
                victims = [u for u in self.users if u.user_id != user.user_id]
                self.rng.shuffle(victims)
                generated = 0
                for victim in victims:
                    generated = self.attack_bola(user, victim, session_id)
                    if generated:
                        break
                if not generated:
                    print(f"  {user.user_id}: BOLA unavailable -> ENUMERATION")
                    self.attack_enumeration(user, session_id)
            elif primary == "BFLA":
                self.attack_bfla(user, session_id)
            elif primary == "MASS_ASSIGNMENT":
                self.attack_mass_assignment(user, session_id)
            elif primary == "ENUMERATION":
                self.attack_enumeration(user, session_id)
            elif primary == "FLOODING":
                self.attack_flooding(user, session_id)
            elif primary == "BUSINESS_FLOW_ABUSE":
                self.attack_business_flow(user, session_id)

            # Second episode for every second user, using a different class.
            if i % 2 == 0:
                secondary = labels[(i + 2) % len(labels)]
                if secondary == "BOLA":
                    victims = [u for u in self.users if u.user_id != user.user_id]
                    self.rng.shuffle(victims)
                    generated = 0
                    for victim in victims:
                        generated = self.attack_bola(user, victim, session_id)
                        if generated:
                            break
                    if not generated:
                        self.attack_enumeration(user, session_id)
                elif secondary == "BFLA":
                    self.attack_bfla(user, session_id)
                elif secondary == "MASS_ASSIGNMENT":
                    self.attack_mass_assignment(user, session_id)
                elif secondary == "ENUMERATION":
                    self.attack_enumeration(user, session_id)
                elif secondary == "FLOODING":
                    self.attack_flooding(user, session_id)
                elif secondary == "BUSINESS_FLOW_ABUSE":
                    self.attack_business_flow(user, session_id)

            # Normal traffic after the attack episode.
            self.normal_episode(user, session_id, self.rng.randint(5, 12))

        return self.events

    def write(self, output: str):
        p = Path(output)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as f:
            for event in self.events:
                f.write(json.dumps(event, separators=(",", ":")) + "\n")

        counts = Counter(e["behavior_label"] for e in self.events)
        users = len(set(e["user_id"] for e in self.events))

        print("\nDataset generation complete")
        print(f"Events: {len(self.events)}")
        print(f"Users: {users}")
        print(f"Output: {p}")
        print("\nBehavior labels:")
        for label, count in sorted(counts.items()):
            print(f"  {label:<24} {count}")

        print("\nAttack coverage:")
        for label in [
            "BOLA", "BFLA", "MASS_ASSIGNMENT",
            "ENUMERATION", "FLOODING", "BUSINESS_FLOW_ABUSE"
        ]:
            print(f"  {label:<24} {counts.get(label, 0)}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--users", type=int, default=30)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--spec", default=DEFAULT_SPEC)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    args = parser.parse_args()

    generator = Generator(
        base_url=args.base_url,
        spec_path=args.spec,
        seed=args.seed,
    )
    generator.generate(args.users)
    generator.write(args.output)


if __name__ == "__main__":
    main()
