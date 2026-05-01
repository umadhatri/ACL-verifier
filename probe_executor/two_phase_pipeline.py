"""
Two-Phase Pipeline.

Orchestrates the full two-phase adaptive probing workflow:
  1. Run positive probes — verify reachability
  2. Run Phase 1 sweep — O(N) isolation check
  3. Identify which users failed Phase 1
  4. Run Phase 2 localisation — only for users who failed Phase 1
  5. Report all violations with precise boundary localisation
"""

import copy
from probe_generator.two_phase_generator import TwoPhaseProbeGenerator, Probe
from probe_executor.policy_executor import PolicyAwareExecutor, ProbeResult, ViolationReporter
from models.db_interface import DatabaseInterface
from static_policy_checker.policy_checker import StaticPolicyChecker

class TwoPhasePipeline:

    def __init__(self, policy, db: DatabaseInterface):
        self.db = db
        self.policy = policy
        self.user_subnet_map = db.get_user_subnet_map()
        self.generator = TwoPhaseProbeGenerator(self.user_subnet_map)
        self.executor = PolicyAwareExecutor(policy)
        self.reporter = ViolationReporter()
        self.static_checker = StaticPolicyChecker(db)

    def run(self, verbose: bool = True) -> dict:
        """
        Execute the full two-phase pipeline.
        Returns a summary dict with probe counts and violations found.
        """
        results = {
            "positive_probe_outcomes": [],
            "phase1_outcomes": [],
            "phase2_outcomes": [],
            "users_with_leaks": [],
            "total_probes_run": 0,
        }

        # --- Positive probes ---
        positive_probes = self.generator.generate_positive_probes()
        positive_probe_outcomes = self.executor.run(positive_probes)
        results["positive_probe_outcomes"] = positive_probe_outcomes
        results["total_probes_run"] += len(positive_probes)
        positive_probe_failure_users = set(o.probe.src_user for o in positive_probe_outcomes if o.result == ProbeResult.FAIL)

        if verbose:
            print("=" * 65)
            print("POSITIVE PROBE RESULTS (reachability verification)")
            print("=" * 65)
            self.reporter.report(positive_probe_outcomes)

        # --- Phase 1 sweep ---
        phase1_probes = self.generator.generate_phase1_probes()
        phase1_outcomes = self.executor.run(phase1_probes)
        results["phase1_outcomes"] = phase1_outcomes
        results["total_probes_run"] += len(phase1_probes)

        # Identify users who failed Phase 1 (isolation leak detected)
        phase1_flagged_users = set(o.probe.src_user for o in phase1_outcomes if o.result == ProbeResult.FAIL)

        # Identify users who are flagged by Static Policy Checker
        static_check_result = self.static_checker.check(self.policy)
        static_checking_flagged_users = set(static_check_result.flagged_users)

        # Flagged users combined from both phase 1 and static policy checking are passed to phase2
        users_with_leaks = list(phase1_flagged_users | static_checking_flagged_users)
        
        results["users_with_leaks"] = users_with_leaks

        if verbose:
            print()
            print("=" * 65)
            print("PHASE 1 SWEEP RESULTS (O(N) isolation check)")
            print("=" * 65)
            self.reporter.report(phase1_outcomes)

            print()
            print()
            static_check_result.report()
            print()
            
            if users_with_leaks:
                print(f"\n→ Leak detected for: {users_with_leaks}")
                print(f"→ Triggering Phase 2 localisation for {len(users_with_leaks)} user(s)...")
            else:
                print("\n→ No leaks detected. Phase 2 not needed.")

        # --- Phase 2 localisation (only if needed) ---
        phase2_flagged_users = set()
        if users_with_leaks:
            phase2_probes = self.generator.generate_phase2_probes(users_with_leaks)
            phase2_outcomes = self.executor.run(phase2_probes)
            results["phase2_outcomes"] = phase2_outcomes
            results["total_probes_run"] += len(phase2_probes)
            phase2_flagged_users = set(o.probe.src_user for o in phase2_outcomes if o.result == ProbeResult.FAIL)

            if verbose:
                print()
                print("=" * 65)
                print("PHASE 2 LOCALISATION RESULTS (targeted boundary testing)")
                print("=" * 65)
                self.reporter.report(phase2_outcomes)

        # --- Final summary ---
        if verbose:
            print()
            print("=" * 65)
            print("PIPELINE SUMMARY")
            print("=" * 65)
            print(f"Total probes run:      {results['total_probes_run']}")
            print(f"  Positive probes:     {len(positive_probes)}")
            print(f"  Phase 1 probes:      {len(phase1_probes)}")
            print(f"  Phase 2 probes:      {len(results['phase2_outcomes'])}")
            print()
            print(f"Reachability failure users: {len(positive_probe_failure_users)}")
            print(f"Isolation failure users: {len(phase2_flagged_users)}")

            if not positive_probe_failure_users and not phase2_flagged_users:
                if static_checking_flagged_users:
                    print()
                    print("Static violations found but no probe failures detected.")
                    print("Likely cause: flagged rule(s) cover unallocated address space or inactive tenants in DB")
                    print("If all flagged destinations are active tenants, investigate static checker logic or probe generation")
                else:
                    print("\n✓ ACL correctly enforces isolation and reachability. No violations found.")
            else:
                print("\n✗ ACL Violations detected.")
                print(f"Recommendation: Review ACL rules for the affected users: {str(positive_probe_failure_users | phase2_flagged_users)}")
            
            print("Note: Violations not affecting isolation/ reachability are reported in Static Checking Report above(Orphan rules, Duplicate rules)")
            # print(f"Users with leaks:      {len(users_with_leaks)}")
            # if not users_with_leaks:
                # print("\n✓ ACL correctly enforces isolation. No violations found.")

        return results


if __name__ == "__main__":
    from synthetic_data.generator import generate_synthetic_db
    from acl_generator.generator import ACLGenerator

    db = generate_synthetic_db(num_students=5, num_instructors=1)
    policy = ACLGenerator(db).generate()

    print("=" * 65)
    print("TEST 1: Clean policy — Phase 2 should never trigger")
    print("=" * 65)
    pipeline = TwoPhasePipeline(policy, db)
    pipeline.run()

    print()
    print("=" * 65)
    print("TEST 2: Overly broad rule — student2 gets full management subnet")
    print("        Phase 1 should catch student2, Phase 2 localises all boundaries")
    print("=" * 65)
    faulty_policy = copy.deepcopy(policy)
    for rule in faulty_policy.acls:
        if len(rule.src) == 1 and rule.src[0] == "student2@":
            rule.dst = ["10.20.0.0/16:*"]
    pipeline2 = TwoPhasePipeline(faulty_policy, db)
    pipeline2.run()

    print()
    print("=" * 65)
    print("TEST 3: Wrong subnet — student1 points to student2's subnet")
    print("        Phase 1 catches student1 via reachability failure on sweep probe")
    print("=" * 65)
    faulty_policy3 = copy.deepcopy(policy)
    for rule in faulty_policy3.acls:
        if len(rule.src) == 1 and rule.src[0] == "student1@":
            rule.dst = ["10.20.3.0/24:*"]
    pipeline3 = TwoPhasePipeline(faulty_policy3, db)
    pipeline3.run()