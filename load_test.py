"""
CloudOps Sentinel: Load Test Generator

Sends concurrent search and browse queries against the GET /resources endpoint
to trigger CPU utilization spikes for HorizontalPodAutoscaler (HPA) validation.
"""
import argparse
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed


def send_query(base_url, query_term):
    url = f"{base_url.rstrip('/')}/resources?query={query_term}"
    start = time.time()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SentinelLoadTest/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            status = resp.status
            duration = time.time() - start
            return True, status, duration
    except urllib.error.HTTPError as e:
        return False, e.code, time.time() - start
    except Exception as e:
        return False, str(e), time.time() - start


def main():
    parser = argparse.ArgumentParser(description="Sentinel HPA Load Test Generator")
    parser.add_argument("--url", default="http://127.0.0.1:5000", help="Target base URL")
    parser.add_argument("--concurrency", type=int, default=20, help="Concurrent client threads")
    parser.add_argument("--requests", type=int, default=200, help="Total requests to dispatch")
    args = parser.parse_args()

    search_terms = ["Kubernetes", "AWS", "Terraform", "Docker", "DevOps", "Guide", "Storage", "Plan"]

    print(f"=== Starting Load Test against {args.url}/resources ===")
    print(f"Concurrency: {args.concurrency} | Total requests: {args.requests}")

    successes = 0
    failures = 0
    durations = []
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = [
            executor.submit(send_query, args.url, search_terms[i % len(search_terms)])
            for i in range(args.requests)
        ]

        for future in as_completed(futures):
            ok, status, duration = future.result()
            if ok:
                successes += 1
                durations.append(duration)
            else:
                failures += 1

    total_time = time.time() - start_time
    avg_duration = sum(durations) / len(durations) if durations else 0

    print("=== Load Test Complete ===")
    print(f"Total time:       {total_time:.2f}s")
    print(f"Successful:       {successes} ({successes/args.requests*100:.1f}%)")
    print(f"Failed:           {failures}")
    print(f"Average latency:  {avg_duration*1000:.2f}ms")
    print(f"Throughput:       {args.requests / total_time:.2f} req/s")


if __name__ == "__main__":
    main()
