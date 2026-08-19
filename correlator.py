def correlate_sources(events):
    """Compare what each log source captured per user"""
    # Group events by actor and source
    by_actor_source = {}
    for e in events:
        actor = e["actor"]
        source = e.get("source_file", "unknown")
        key = (actor, source)
        if key not in by_actor_source:
            by_actor_source[key] = []
        by_actor_source[key].append(e)
    
    # Get all actors and sources
    actors = list(set(e["actor"] for e in events))
    sources = list(set(e.get("source_file", "unknown") for e in events))
    
    correlations = []
    
    for actor in actors:
        actor_sources = {}
        for source in sources:
            key = (actor, source)
            if key in by_actor_source:
                actor_sources[source] = by_actor_source[key]
        
        if len(actor_sources) < 2:
            continue  # Only in one source, nothing to correlate
        
        correlation = {
            "actor": actor,
            "sources": {},
            "unique_actions": {},
            "overlapping_timestamps": []
        }
        
        # What actions appear in each source
        for source, source_events in actor_sources.items():
            actions = [e["action"] for e in source_events]
            targets = [e["target"] for e in source_events if e["target"] != "N/A"]
            correlation["sources"][source] = {
                "event_count": len(source_events),
                "actions": actions,
                "targets": targets
            }
        
        # Find actions unique to each source
        all_source_names = list(actor_sources.keys())
        for source in all_source_names:
            source_actions = set(a for a in correlation["sources"][source]["actions"])
            other_actions = set()
            for other_source in all_source_names:
                if other_source != source:
                    other_actions.update(correlation["sources"][other_source]["actions"])
            unique = source_actions - other_actions
            if unique:
                correlation["unique_actions"][source] = list(unique)
        
        correlations.append(correlation)
    
    return correlations

def print_correlations(correlations):
    """Print cross-source correlation analysis"""
    if not correlations:
        print("\nNo cross-source correlations found.")
        return
    
    print(f"\n{'#'*60}")
    print(f" CROSS-SOURCE CORRELATION ANALYSIS")
    print(f"{'#'*60}")
    
    for corr in correlations:
        actor = corr["actor"]
        print(f"\n{'='*60}")
        print(f" {actor}")
        print(f"{'='*60}")
        
        for source, info in corr["sources"].items():
            print(f"\n  [{source}] — {info['event_count']} events")
            print(f"    Actions: {', '.join(info['actions'])}")
            if info["targets"]:
                print(f"    Targets: {', '.join(info['targets'][:5])}")
                if len(info["targets"]) > 5:
                    print(f"    ... and {len(info['targets']) - 5} more")
        
        if corr["unique_actions"]:
            print(f"\n  Actions captured by only ONE source:")
            for source, actions in corr["unique_actions"].items():
                print(f"    Only in {source}: {', '.join(actions)}")