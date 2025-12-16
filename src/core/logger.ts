import { createLogger, format, transports } from "winston";
import * as fs from "fs";
import { config } from "./config.js";

if (!fs.existsSync(config.paths.logs)) {
  fs.mkdirSync(config.paths.logs, { recursive: true });
}

export const logger = createLogger({
  level: config.features.verboseLogging ? "debug" : "info",
  format: format.combine(format.timestamp(), format.json()),
  transports: [
    new transports.File({ filename: `${config.paths.logs}/error.log`, level: "error" }),
    new transports.File({ filename: `${config.paths.logs}/combined.log` }),
  ],
});

if (config.isDev) {
  logger.add(new transports.Console({
    format: format.combine(format.colorize(), format.simple()),
    stderrLevels: ["error", "warn", "info", "debug"],
  }));
}

export function createChildLogger(ctx: string) { 
  return logger.child({ context: ctx }); 
}
