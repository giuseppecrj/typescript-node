export default {
  roots: ["<rootDir>/src"],
  transform: {
    "^.+\\.tsx?$": "ts-jest",
  },

  transformIgnorePatterns: ["/node_modules/.*"],

  clearMocks: true,
  collectCoverage: false,
  globals: {
    "ts-jest": {
      diagnostics: false,
    },
  },
};
