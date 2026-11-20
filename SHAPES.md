# Geometric transforms and subdivision

## Shape options

- `TriangleTransform`, `PentagonTransform`, `HexagonTransform`, `OctagonTransform`.
- `PolygonTransform` is an alias for `HexagonTransform`.
- `RegularPolygonTransform<N>` supports compile-time side counts from 3 through 64, including `RegularPolygonTransform<4>`.
- `SquareTransform` rotates rows, columns, recursively selected square patches, and Bresenham-rasterized line segments.
- `CircleTransform` uses elliptical radial bands, angular sweeps, adjacent-band exchanges, and Bresenham center-to-edge rays.

```cpp
using Cipher = genetic_cipher::GeneticCipher<
    genetic_cipher::PushMode,
    genetic_cipher::SquareTransform,
    genetic_cipher::PopMode,
    genetic_cipher::PushMode,
    genetic_cipher::CircleTransform,
    genetic_cipher::Diffuse,
    genetic_cipher::PopMode,
    genetic_cipher::TriangleTransform>;
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
// Feed a container to cipher.encrypt(container).
// Decryption needs identical secrets, operation order, input mode, and settings.
```

## Geometry

All transforms use a floor(sqrt(element_count)) square grid; an incomplete-grid
tail remains fixed. Grid lines use Bresenham rasterization so each plotted path
is a reversible ordered list of element indices.

Circles assign covered elements to non-overlapping elliptical radial bands,
order each band by angle, rotate the bands, exchange corresponding positions
between neighboring bands, and rotate radial Bresenham sweeps. Squares rotate
selected rows and columns, subdivide patches into quadrants, and rotate
randomly sized pieces and plotted lines.

Regular polygons rasterize their edges and fill their interiors. Subdivision
recursively selects spatial quadrants; each region is ordered geometrically
and split into pseudo-random-sized rotation pieces. Triangles additionally
partition elements by nearest vertex, rotate center-to-vertex medians, and
exchange matching positions between two vertex regions. These are reversible
permutations of elements; with `BitMode::BIT_1`, those elements are individual
bits, while wider modes group more bits into each geometric element.

| Setting | Meaning for the new polygons |
| --- | --- |
| `coverage_percentage` | 0–100; scales the polygon radius by sqrt(percentage / 100). This is approximate geometric coverage, not an exact percentage of elements. Zero disables the shape. |
| `subdivision_percentage` | 0–100; selects a percentage of child quadrants in a PRNG-shuffled order. Any positive value selects at least one child. |
| `recursive_subdivisions` | Enables child-region traversal. False processes only the root polygon region. |
| `recursion_depth` | Maximum child depth; root is depth zero. Zero processes only the root. Regions also stop when their geometry cannot shrink. |
| `min_subdivision_size` | Stop splitting at or below this element count; must be at least two. |
| `max_subdivision_size` | Maximum rotation-piece size within each region; must be at least min_subdivision_size. |

Percentages must be finite and in range; invalid distributions throw
`std::invalid_argument`. Matching settings are required for decryption. Shape
operations are generated from the same deterministic PRNG sequence and replayed
in reverse order for decryption.

## Bit widths and mode stack

Each shape receives the container's actual bit mode. That mode determines the
element count and thus the grid geometry. `PushMode`, `PopMode`, `SwitchMode`,
`ModeCycle`, and `ModeFeedback` now apply reversible PRNG masks in lanes chosen
from their selected modes, in addition to maintaining the stack. Ordinary
operations executed while a pushed mode is active are wrapped in reversible
lane masks selected by that mode; nested mode-stack states are reproduced for
decryption. The mode width affects the transform's lane layout, not the
container's element width. These operations do not claim cryptographic security.

Tests cover the built-in polygons, all ten supported scalar widths, line
rasterization, shape and mode-stack round trips, and output changes across
widths. Successful round trips do not establish stronger cryptographic
security. The authentication and key-derivation limitations in the security
assessment still apply.
