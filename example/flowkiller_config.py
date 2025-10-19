# Need to ensure we don't kill unrelated processes
c.FlowKiller.unique_destinations_threshold = 10
c.FlowKiller.lookback_duration_seconds = 2

# Useful for debugging
c.FlowKiller.log_connects = True

c.FlowKiller.banned_ipv4_file = "/example/banned_ipv4.txt"
