import { createRequire } from "node:module";

// package.json sits one level above both src/ and dist/.
const require = createRequire(import.meta.url);
export const VERSION: string = (require("../package.json") as { version: string }).version;
