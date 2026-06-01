## What is a Cluster in Dart AOT?

A **cluster** is the fundamental serialization unit in Dart's AOT snapshot format. It's a group of objects of the **same class/type** that are serialized together using a shared encoding scheme .

### The Two-Phase Cluster Serialization

Dart AOT snapshots use a two-phase process where clusters are the core organizational structure:

```
Phase 1: ALLOC  →  Phase 2: FILL
```

**Phase 1: Allocation (Alloc)**
- Walks through clusters in **Class ID (CID) order**
- Each cluster declares: *"I contain N objects of class X"*
- Assigns sequential **reference IDs** to every object
- **No actual data is read yet** - only counts and reservations

**Phase 2: Fill**
- Walks through the same clusters again
- Reads actual field values: string bytes, reference IDs, integers
- Encoding varies by object type and Dart version 

### Cluster Structure

```
Cluster Header:
  - CID (Class ID): Identifies the class type (e.g., String, List, Code)
  - Count: Number of objects in this cluster
  - Flags: Encoding options

Cluster Body (Fill Phase):
  - Object 1 field data
  - Object 2 field data
  - ... N times
```

### Why Clusters Exist

1. **Deduplication**: Objects of the same type share encoding logic
2. **Sequential Access**: Better cache locality during deserialization
3. **Compression of Metadata**: Class information stored once per cluster, not per object
4. **Version Flexibility**: Different Dart versions can change cluster handlers independently 

### Cluster Types (CID Examples)

| CID | Class | Description |
|-----|-------|-------------|
| 1-5 | Object, Class, Function, etc. | VM internal classes |
| 50+ | String variants | One-byte, two-byte strings |
| 60+ | Array types | TypedData, GrowableObjectArray |
| 100+ | Code objects | Compiled function machine code |

### Real-World Example from unflutter

When unflutter parses a snapshot:
```
1. Reads snapshot header → finds version hash
2. Loads CID table → maps CID → cluster handler
3. For each cluster:
   - ALLOC: Reads count, assigns reference IDs
   - FILL: Parses field values based on CID-specific grammar
4. Result: Complete object graph with all strings, classes, functions 
```

### Cluster Grammar Constraints

The unflutter tool treats clusters as **constraint-based parsing**:
- **ELF invariants** eliminate invalid binaries
- **Snapshot magic** (`0xf5f5dcdc`) confirms Dart format
- **Version hash** selects exact CID table and encoding
- **Cluster alloc counts** fix object population
- **Fill parsing** recovers field values 

### Key Insight for Reverse Engineering

**Clusters are why plain text extraction works**: Because clusters group objects by type, all strings of a certain type are stored in sequence with predictable offsets. This allows tools like Blutter and unflutter to walk the cluster and extract every string without executing the code.

The cluster format is **deterministic and version-specific**, which is why reverse engineering tools need to handle format changes across Dart versions explicitly .
