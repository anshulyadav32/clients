import { deepFreeze } from "@bitwarden/common/tools/util";

import { ImportType } from "../models";

import { Loader, Instructions } from "./data";
import { DataLoader, ImporterMetadata, InstructionLink } from "./types";

// Attempt to load metadata from desktop-napi, guaranteed to fail on web and in tests, expected to succeed on desktop
let chromium_importer_metadata: { json: () => string } | undefined;
type ChromiumImporterMetadata = {
  chromium_importer_metadata?: { json: () => string };
};
try {
  // __filename is defined for desktop only
  if (typeof __filename !== "undefined") {
    const nodeRequire = (0, eval)("require") as (id: string) => unknown;
    const native = nodeRequire("@bitwarden/desktop-napi") as ChromiumImporterMetadata;
    if (
      native &&
      native.chromium_importer_metadata &&
      typeof native.chromium_importer_metadata.json === "function"
    ) {
      chromium_importer_metadata = native.chromium_importer_metadata as { json: () => string };
    }
  }
} catch {
  // guaranteed to occur in import.service.ts and util.spec.ts, mocks have been added there
  // TODO remove those mocks and test Rust code using Rust code
  chromium_importer_metadata = undefined;
}

type NativeImporter = {
  id: string;
  loaders: string[];
  instructions: string;
};

function mapLoader(name: string): DataLoader {
  switch (name) {
    case "file":
      return Loader.file;
    case "chromium":
      return Loader.chromium;
    default:
      throw new Error(`Unknown loader from native module: ${name}`);
  }
}

function mapInstructions(name: string): InstructionLink | undefined {
  switch (name) {
    case "chromium":
      return Instructions.chromium;
    default:
      return undefined;
  }
}

let fromNative: Partial<Record<ImportType, ImporterMetadata>> | undefined;
if (chromium_importer_metadata) {
  const rawJson: string = chromium_importer_metadata.json();
  const raw: Record<string, NativeImporter> = JSON.parse(rawJson);

  const entries = Object.entries(raw).map(([id, meta]) => {
    const loaders = meta.loaders.map(mapLoader);
    const instructions = mapInstructions(meta.instructions);
    const mapped: ImporterMetadata = {
      type: id as ImportType,
      loaders,
      ...(instructions ? { instructions } : {}),
    };
    return [id, mapped] as const;
  });

  fromNative = Object.fromEntries(entries) as Partial<Record<ImportType, ImporterMetadata>>;
}
/** Describes which loaders are available for each import type */
export const Importers: Partial<Record<ImportType, ImporterMetadata>> = deepFreeze(
  fromNative ?? {},
);
