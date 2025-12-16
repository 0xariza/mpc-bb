import * as fs from "fs";
import * as path from "path";
import { FileError, config } from "../core/index.js";

export function exists(p: string): boolean { 
  return fs.existsSync(p); 
}

export function isDirectory(p: string): boolean { 
  return exists(p) && fs.statSync(p).isDirectory(); 
}

export function isFile(p: string): boolean { 
  return exists(p) && fs.statSync(p).isFile(); 
}

export function readFile(p: string): string {
  if (!exists(p)) throw new FileError("File not found", p);
  const size = fs.statSync(p).size;
  if (size > config.limits.maxFileSize) {
    throw new FileError(`File too large: ${size}`, p);
  }
  return fs.readFileSync(p, "utf-8");
}

export function findSolidityFiles(dir: string, recursive = true): string[] {
  if (!isDirectory(dir)) throw new FileError("Not a directory", dir);
  
  const results: string[] = [];
  
  const scan = (d: string) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (e.name.startsWith(".") || e.name === "node_modules") continue;
      const full = path.join(d, e.name);
      if (e.isDirectory() && recursive) scan(full);
      else if (e.isFile() && e.name.endsWith(".sol")) results.push(full);
    }
  };
  
  scan(dir);
  return results;
}

export function getFileInfo(p: string) {
  const content = readFile(p);
  return { 
    path: p, 
    name: path.basename(p), 
    size: fs.statSync(p).size, 
    lines: content.split("\n").length 
  };
}

export function ensureDirectory(p: string) { 
  if (!exists(p)) fs.mkdirSync(p, { recursive: true }); 
}

export function relativePath(base: string, full: string) { 
  return path.relative(base, full); 
}
