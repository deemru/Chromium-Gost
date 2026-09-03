#!/usr/bin/env python3

import pathlib
import sys


def byte_array(data):
    values = [f"0x{byte:02x}" for byte in data]
    return "\n".join(
        "    " + ", ".join(values[offset : offset + 12]) + ","
        for offset in range(0, len(values), 12)
    )


def main():
    header_path = pathlib.Path(sys.argv[1])
    source_path = pathlib.Path(sys.argv[2])
    inputs = [pathlib.Path(value) for value in sys.argv[3:]]

    header_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.parent.mkdir(parents=True, exist_ok=True)

    header_path.write_text(
        """#ifndef CHROME_BROWSER_UI_STARTUP_BUNDLED_EXTENSIONS_DATA_H_
#define CHROME_BROWSER_UI_STARTUP_BUNDLED_EXTENSIONS_DATA_H_

#include <cstdint>
#include <string_view>

#include "base/containers/span.h"

namespace chromium_gost {

base::span<const uint8_t> GetBundledExtensionCrx(std::string_view id);

}  // namespace chromium_gost

#endif  // CHROME_BROWSER_UI_STARTUP_BUNDLED_EXTENSIONS_DATA_H_
""",
        encoding="utf-8",
    )

    arrays = []
    branches = []
    for index, input_path in enumerate(inputs):
        extension_id = input_path.name.split("-", 1)[0]
        symbol = f"kBundledExtension{index}"
        arrays.append(
            f"constexpr uint8_t {symbol}[] = {{\n{byte_array(input_path.read_bytes())}\n}};"
        )
        branches.append(
            f'  if (id == "{extension_id}") {{\n'
            f"    return base::span({symbol});\n"
            "  }"
        )

    source_path.write_text(
        """#include "chrome/browser/ui/startup/bundled_extensions_data.h"

namespace chromium_gost {
namespace {

"""
        + "\n\n".join(arrays)
        + """

}  // namespace

base::span<const uint8_t> GetBundledExtensionCrx(std::string_view id) {
"""
        + "\n".join(branches)
        + """
  return {};
}

}  // namespace chromium_gost
""",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
