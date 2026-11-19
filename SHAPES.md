<!-- coderabbit-ai-generated:v1 -->

# Polygon shapes and recursive subdivision

## Shape options

- `TriangleTransform`, `PentagonTransform`, `HexagonTransform`, `OctagonTransform`.
- `PolygonTransform` is an alias for `HexagonTransform`.
- `RegularPolygonTransform<N>` supports compile-time side counts from 3 through 64, including `RegularPolygonTransform<4>` for a polygon square. Existing `SquareTransform` retains its original row/column algorithm.

```cpp
using Cipher = genetic_cipher::GeneticCipher<
    genetic_cipher::PolygonTransform,
    genetic_cipher::PushMode,
    genetic_cipher::TriangleTransform,
    genetic_cipher::PushMode,
    genetic_cipher::Diffuse,
    genetic_cipher::PopMode,
    genetic_cipher::BitwiseXor,
    genetic_cipher::PopMode>;
Cipher cipher;
cipher.set_password(std::string("example-passphrase"));
cipher.set_electronic_password(std::string("example-device-key"));
auto& p = cipher.settings().shape_distribution;
p.coverage_percentage = 100;
p.subdivision_percentage = 100;
p.recursive_subdivisions = true;
p.recursion_depth = 3;
p.min_subdivision_size = 8;
p.max_subdivision_size = 1024;
// Feed a container to cipher.encrypt(container), as in demo.cpp.
// Decryption needs identical secrets, operation order, and distribution settings.
```

## How subdivision works

Polygons are inscribed on the same floor(sqrt(element_count)) square grid used by the existing shapes. Positions outside the rasterized polygon and the incomplete-grid tail stay fixed. Inside each region, keyed rotations move elements without changing their values.

A parent region splits into four quadrants. Intersecting each quadrant with the parent's polygon creates smaller polygon regions. The implementation uses an explicit traversal stack, applies parent rotations before child rotations, and reverses the entire sequence for decryption. Overlapping parent/child regions therefore remain reversible.

| Setting | Meaning for the new polygons |
| --- | --- |
| `coverage_percentage` | 0–100; scales the polygon radius by sqrt(percentage / 100). This is approximate geometric coverage, not an exact percentage of elements. Zero disables the shape. |
| `subdivision_percentage` | 0–100; selects floor(4 × percentage / 100) child quadrants at each split, in top-left, top-right, bottom-left, bottom-right order. Parent rotations still run. |
| `recursive_subdivisions` | Enables child-region traversal. False processes only the root polygon. |
| `recursion_depth` | Maximum child depth; root is depth zero. Zero processes only the root. Regions also stop when their geometry cannot shrink. |
| `min_subdivision_size` | Stop splitting at or below this element count; must be at least two. |
| `max_subdivision_size` | Maximum rotation-group size within each region; must be at least min_subdivision_size. Larger regions rotate consecutive groups separately. |

Percentages must be finite and in range; invalid distributions throw `std::invalid_argument`. Matching settings are required for decryption. These semantics apply to the new polygon transforms; the existing square and circle algorithms retain their behavior. Traversal terminates even with a very large depth setting because region dimensions shrink. Plans store rotations for reversal, using memory proportional to the participating elements across visited depths.

## Push/pop and recursion

The existing `PushMode` and `PopMode` tags manipulate an internal mode stack. `SwitchMode`, `ModeCycle`, and `ModeFeedback` also operate on that stack. Current data operations read the container's global mode, so these tags do not change element width or initiate recursive shape calls. A nested sequence can round-trip without proving dynamic-width processing. Polygon recursion is controlled by the distribution settings above.

Tests cover nested push/pop surrounding polygons and data transforms, reused and fresh decryptors, stack-only sequences, and popping the base stack. Implementing dynamic-width or recursive pipeline execution through stack tags would require a separate behavioral and format design.

## Validation

`shape_tests` covers five polygon configurations across all ten scalar widths and four lengths, permutation preservation, incomplete-grid tails, recursion depth and termination, distribution percentages, invalid settings, deterministic repeated calls, and nested mode stacks. Run all suites with the CMake commands in [the security assessment](SECURITY_ASSESSMENT.md). `ENABLE_SANITIZERS=ON` now instruments both `engine_tests` and `shape_tests`.

Additional shapes provide transformation options; these tests do not establish stronger cryptographic security. The authentication and key-derivation limitations in the security assessment still apply.
