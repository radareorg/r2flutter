# Dart AOT ARM64 Calling Convention Report

**Analysis Date:** February 2026  
**Target Architecture:** ARM64 (AArch64)  
**Compiler:** Dart SDK AOT Compiler  
**Platform:** Apple macOS (Mach-O format)

## Executive Summary

This report documents the ARM64 calling conventions and code generation patterns used by the Dart AOT compiler when compiling classes with methods and fields. Analysis was performed by compiling five test programs to Mach-O snapshots and disassembling with `otool`.

---

## 1. ARM64 Calling Convention Basics

### 1.1 Register Usage

Dart AOT follows the ARM64 EABI (Embedded ABI) with custom extensions:

| Register | Purpose | Preserved? | Notes |
|----------|---------|-----------|-------|
| x0-x7 | Arguments (0-7) / Return | No | x0 = return value |
| x8-x18 | Temporary | No | Caller-save |
| x19-x28 | General purpose | **Yes** | Callee must preserve |
| x26 | Thread state | **Yes** | Dart VM special: globals |
| x27 | Object pool | **Yes** | Dart VM special: vtable |
| x29 | Frame pointer (FP) | **Yes** | ABI requirement |
| x30 | Link register (LR) | **Yes** | Return address |
| x15 | Stack pointer alt | N/A | Dart uses x15, not sp |
| x22 | Null singleton | N/A | Dart VM: null marker |

### 1.2 Key Dart VM Registers

**x26 (Thread/Isolate Pointer):**
```
ldr     x5, [x26, #0x4c0]    ; Load VM runtime function at offset +0x4c0
ldr     x30, [x26, #0x208]   ; Load callback address at offset +0x208
blr     x30                  ; Branch to loaded address
```

**x27 (Object Pool / Class Table):**
```
ldr     x4, [x27, #0xbe0]    ; Load class/pool entry at offset +0xbe0
```

**x22 (Null Singleton):**
```
cmp     x9, x22              ; Compare register with null
b.ne    0x4c820              ; Branch if not equal to null
```

---

## 2. Function Prologue and Epilogue

### 2.1 Prologue Pattern (Entry)

```asm
; PROLOGUE - All user functions begin like this:
stp     x29, x30, [x15, #-0x10]!   ; Save FP and LR to stack
                                    ; Pre-decrement: [x15 -= 16]
mov     x29, x15                    ; Set new frame pointer

; Stack overflow check (always present):
sub     x15, x15, #0x70             ; Allocate 112 bytes for locals
ldr     x16, [x26, #0x48]           ; Load stack limit from thread
cmp     x15, x16                    ; Check if SP below limit
b.ls    0x4ca2c                     ; Branch to overflow handler if LS
```

**Explanation:**
- `stp` (Store Pair): Saves two 64-bit registers atomically
- `#-0x10]!` (pre-decrement): Stack pointer decreases before store
- `sub x15, x15, #SIZE`: Allocates space for local variables
- Stack overflow check is **mandatory** in Dart

### 2.2 Epilogue Pattern (Exit)

```asm
; EPILOGUE - Return sequence:
mov     x15, x29                    ; Restore SP from FP
ldp     x29, x30, [x15], #0x10     ; Load FP/LR, post-increment SP
ret                                 ; Return to caller
```

**Explanation:**
- `ldp` (Load Pair): Restores two registers atomically
- `[x15], #0x10` (post-increment): Stack pointer increases after load
- `ret`: Implicit branch to x30 (return address)

### 2.3 Example: Simple Constructor

From `01_simple_class.dart`:

```dart
class Point {
  int x;
  int y;
  Point(this.x, this.y);
}
```

Expected constructor prologue:
```asm
stp     x29, x30, [x15, #-0x10]!
mov     x29, x15
sub     x15, x15, #0x50            ; Allocate space for locals
ldr     x16, [x26, #0x48]          ; Check stack
cmp     x15, x16
b.ls    overflow_stub
; ... constructor body
mov     x15, x29                   ; Exit prep
ldp     x29, x30, [x15], #0x10    ; Restore
ret
```

---

## 3. Parameter Passing & Stack Frames

### 3.1 Argument Registers (x0-x7)

First 8 arguments go in x0-x7:

```asm
; Calling convention for: int add(int a, int b)
; Called with: add(5, 10)
mov     x0, #5      ; x0 = argument a
mov     x1, #10     ; x1 = argument b
bl      add_func    ; Branch with link (saves x30)

; Inside add_func prologue:
stp     x29, x30, [x15, #-0x10]!
mov     x29, x15
; x0 and x1 already contain arguments
add     x0, x0, x1  ; x0 = 5 + 10 = 15
; Return x0 implicitly at epilogue
```

### 3.2 Stack Frame Layout

For a function allocating N bytes of locals:

```
        Memory Layout (grows downward)
        ┌─────────────────┐
        │  Caller's data  │
FP+8    ├─────────────────┤
        │  Saved LR (x30) │
FP+0    ├─────────────────┤
        │  Saved FP (x29) │ ← FP points here
FP-8    ├─────────────────┤
        │  Local var 1    │
FP-16   ├─────────────────┤
        │  Local var 2    │
FP-N    ├─────────────────┤
        │  SP (x15) ↓     │
        └─────────────────┘
```

**Example: 4 locals, 32 bytes allocated:**

```asm
stp     x29, x30, [x15, #-0x10]!   ; FP-0, FP-8
mov     x29, x15
sub     x15, x15, #0x20            ; Allocate 32 bytes
ldr     x16, [x26, #0x48]
cmp     x15, x16
b.ls    overflow

; Now FP-0 = saved FP, FP-8 = saved LR
; FP-16 to FP-32 available for locals

; Example local access:
stur    x0, [x29, #-0x10]          ; Store local[0]
ldur    x0, [x29, #-0x10]          ; Load local[0]
```

### 3.3 Storing Unscaled Offsets

Dart prefers `stur`/`ldur` (unscaled) for arbitrary offsets:

```asm
; stur/ldur: signed 9-bit offset (-256 to +255 bytes)
stur    x4, [x29, #-0x20]          ; Store with offset -32
ldur    x1, [x0, #0x1f]            ; Load with offset +31

; Typically used for:
; - Local variables (negative offsets from FP)
; - Object fields (positive offsets from object ptr)
; - Small offsets that don't fit in ldr/str scaled format
```

---

## 4. Object Layout & Field Access

### 4.1 Object Header (Metadata at Negative Offsets)

Objects store type information at negative offsets:

```asm
ldur    x16, [x0, #-0x1]           ; Load tag at offset -1
ubfx    x16, x16, #12, #20         ; Extract bits [12:31]
; x16 now contains field count/type info
```

**Header Structure:**
```
[Object Pointer] x0
    ↓
x0-1 byte:  Type tag + flags (16 bits)
            Bits [12:31]: Field count or type ID
x0-8 bytes: Class descriptor pointer
```

### 4.2 Field Access Pattern

From `04_multiple_fields.dart`:

```dart
class Rectangle {
  int width;    // offset 0x10?
  int height;   // offset 0x18?
  int depth;    // offset 0x20?
  int color;    // offset 0x28?
}
```

Assembly for field lookup:

```asm
ldr     x0, [x29, #0x10]           ; Load Rectangle object
ldur    x1, [x0, #0x1f]            ; Load class descriptor at +0x1f
ldur    x2, [x1, #0x27]            ; Load field table at +0x27
```

**Access Pattern:**
1. Load object reference into x0
2. Load class descriptor from object metadata
3. Load field offset table from class
4. Use offsets to access field values

### 4.3 Nested Object Access

For accessing fields of fields:

```asm
ldr     x0, [x29, #0x18]           ; Load outer object
ldur    x1, [x0, #0x1f]            ; Load inner object reference
ldur    x2, [x1, #0x27]            ; Load field from inner object
```

---

## 5. Method Dispatch & Virtual Calls

### 5.1 Instance Method Calls

Pattern for calling methods on objects (virtual dispatch):

```asm
; Call method on object in x0
ldr     x0, [x29, #0x10]           ; Load receiver object
ldur    x1, [x0, #0x1f]            ; Load class descriptor
ldur    x2, [x1, #0x27]            ; Load method table (vtable)
ldur    x30, [x2, #0x7]            ; Load specific method address
blr     x30                         ; Call method
```

**Sequence:**
1. Object → Class Descriptor (via header)
2. Class → Method Table (vtable)
3. Method Table → Method Address
4. `blr x30`: Indirect branch (sets x30 as return address automatically)

### 5.2 Static Method Calls

Static methods use direct addressing:

```asm
; From 05_static_method.dart: Math.add(100, 50)
mov     x0, #100                   ; x0 = first arg
mov     x1, #50                    ; x1 = second arg
ldr     x16, [x27, #OFFSET]        ; Load static method address
blr     x16                         ; Call (return in x0)
```

---

## 6. Type Checking & Guard Patterns

### 6.1 Arity Checking (for Closures)

```asm
ldur    x16, [x0, #-0x1]           ; Load closure metadata
ubfx    x16, x16, #12, #20         ; Extract arity (field count)
cmp     x5, x16, lsl #1            ; Compare with shifted arg count
b.ne    error_handler              ; Wrong number of args
```

**Explanation:**
- `ubfx` (Unsigned Bit Field Extract): Extract bits [12:31]
- `lsl #1`: Shift left (arity tag adjustment)
- `b.ne`: Branch if not equal (type mismatch)

### 6.2 Type Tag Extraction

```asm
ldur    w3, [x2, #0x47]            ; Load 32-bit type info
ubfiz   x4, x3, #1, #32            ; Box: shift left 1
and     x3, x4, #0x1fff8           ; Mask to get tagged value
```

### 6.3 Common Guard Patterns

```asm
; Check if value is null
cmp     x9, x22                    ; Compare with null (x22)
b.eq    null_handler               ; Jump if null

; Check if integer
ldur    x16, [x0, #-0x1]
ubfx    x16, x16, #12, #20
cmp     x16, #0x4                  ; Type ID 4 = integer?
b.ne    type_error

; Check if array bounds
ldur    x16, [x0, #-0x1]
ubfx    x16, x16, #12, #20
cmp     x5, x16, lsl #1            ; Array length check
b.hs    bounds_error               ; Half-open range check
```

---

## 7. Bit Manipulation & Tagging

### 7.1 Small Integer Tagging

Dart uses single-bit tagging for small integers:

```asm
; Value 10 → tagged 20 (multiply by 2)
mov     x0, #10
lsl     x0, x0, #1                 ; x0 = 20 (tagged)

; Or using ubfiz:
mov     x3, #10
ubfiz   x4, x3, #1, #32            ; Shift left by 1
```

**Untagging:**
```asm
asr     x5, x3, #3                 ; Arithmetic shift right by 3
lsl     x5, x5, #1                 ; Re-encode
```

### 7.2 Bit Field Operations

```asm
ubfx    x16, x16, #12, #20         ; Extract bits [12:31]
ubfiz   x2, x3, #1, #16            ; Insert with shift
sbfx    x5, x3, #17, #9            ; Signed extraction
```

---

## 8. Branching & Control Flow

### 8.1 Conditional Branch Patterns

```asm
; Branch if zero
cbz     x4, label                  ; Skip if x4 == 0

; Branch if not zero
cbnz    x4, label                  ; Skip if x4 != 0

; Compare and branch
cmp     x5, #0x4
b.ne    different               ; Branch not equal
b.eq    same                    ; Branch equal
b.ls    less_or_same            ; Less/same (unsigned)
b.hs    higher_or_same          ; Higher/same (unsigned)
b.lt    less_than               ; Less than (signed)
b.gt    greater_than            ; Greater than (signed)
```

### 8.2 Table-based Dispatch

Observed in complex method resolution:

```asm
mov     x16, #0xe01c
movk    x16, #0x4, lsl #16         ; Build 0x4e01c
orr     x2, x2, x16                ; OR into position
stur    x2, [x3, #-0x1]            ; Store type tag
```

---

## 9. Memory Barriers & Synchronization

### 9.1 Memory Barriers in Field Assignment

```asm
; Thread-safe field write:
dmb     ishst                       ; Memory barrier
stur    x3, [x1, #0x7]             ; Store after barrier
```

**Used for:**
- Write barriers in GC-heavy code
- Write ordering in concurrent scenarios

---

## 10. Specific Code Patterns Observed

### 10.1 Object Allocation Pattern

```asm
; Allocate new object (from CloneSuspendState stub):
ldr     x1, [x26, #0x58]           ; Current heap pointer
add     x2, x2, x1                 ; Calculate new position
ldr     x16, [x26, #0x60]          ; Load heap limit
cmp     x2, x16                    ; Check overflow
b.hs    gc_handler                 ; GC if over limit
str     x2, [x26, #0x58]           ; Update heap pointer
```

### 10.2 Method Resolution With Caching

```asm
; Fast path: Direct method call if type matches
cmp     x9, x22
b.ne    slow_path                  ; Null or type mismatch
mov     x1, x11                    ; Use cached method ptr
mov     x0, x8                     ; Setup receiver
b       method_entry
```

### 10.3 Stack Frame Save/Restore

```asm
; Save multiple values:
stp     x2, x1, [x15, #-0x10]!     ; Save pair, pre-decrement
stp     x0, x2, [x15, #-0x10]!     ; Another pair
str     x22, [x15, #-0x8]!         ; Single value

; Restore:
ldr     x0, [x15], #0x8            ; Load, post-increment
ldp     x2, x0, [x15], #0x8        ; Load pair
```

---

## 11. Test Program Observations

### Test 1: Simple Class (`01_simple_class.dart`)

```dart
class Point {
  int x, y;
  Point(this.x, this.y);
  int getSum() { return x + y; }
}
```

**Patterns:**
- Constructor: Field initialization with direct stores
- Method: Field loads, addition, implicit return in x0

### Test 2: Method Calls (`02_method_call.dart`)

```dart
int chain(int a, int b, int c) {
  return add(a, b) + multiply(b, c);
}
```

**Patterns:**
- Two sequential calls
- Result saved/restored across calls
- Addition of two method results

### Test 3: Inheritance (`03_inheritance.dart`)

```dart
class Dog extends Animal {
  void speak() { ... }
}
```

**Patterns:**
- Vtable-based dispatch
- Polymorphic method calls

### Test 4: Multiple Fields (`04_multiple_fields.dart`)

```dart
class Rectangle {
  int width, height, depth, color;
}
```

**Patterns:**
- Field offset encoding
- Bulk field access
- Field packing optimization

### Test 5: Static Methods (`05_static_method.dart`)

```dart
static int add(int a, int b) { return a + b; }
```

**Patterns:**
- No receiver object (this = unused)
- Direct addressing via object pool

---

## 12. Summary Table: ARM64 ABI Deviations

| Feature | Standard ARM64 | Dart AOT | Reason |
|---------|---|---|---|
| Stack pointer | `sp` | `x15` | VM compatibility |
| Null marker | Not special | `x22` | GC optimization |
| Object pool | Not used | `x27` | JIT/AOT interop |
| Thread state | TLS | `x26` | Fast access |
| Stack checks | Optional | Mandatory | Safety |
| Integer tagging | N/A | LSB=0 | 32-bit optimization |
| Field offsets | 3-bit aligned | Arbitrary | Flexibility |
| Method dispatch | N/A | Header walk | OOP support |

---

## 13. Performance Implications

1. **Method calls:** 3-4 instructions overhead (load class, load vtable, load method)
2. **Field access:** 1-3 instructions (1 for direct, 3 for computed)
3. **Stack frame:** Always 16-byte aligned, prologue/epilogue = 6-8 instructions
4. **Integer boxing:** 1-2 instructions (shift operations)
5. **Memory barriers:** 1 instruction when needed

---

## 14. Debugging Notes

**For reverse engineering Dart binaries:**

```bash
# Check for x26/x27 registers to confirm Dart VM
otool -tv snapshot | grep "x26"

# Look for characteristic patterns:
# - "stp x29, x30, [x15"  → Dart function
# - "ldur x16, [x0, #-0x1]" → Type checking
# - "ldr x30, [x26" → VM callback
```

---

**Report compiled:** Feb 22, 2026  
**Compiler version:** Dart 3.x AOT  
**Analysis tool:** otool (macOS)
