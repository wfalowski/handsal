// Entry point bootstrap.
//
// `./env.js` loads .env and validates process.env as a side effect of being
// imported. It MUST run before any module that reads process.env during
// evaluation — in particular @handsal/db, whose connection pool is created at
// import time from process.env.DATABASE_URL. If the database package were
// imported first, the pool would be built before .env is loaded.
//
// Loading env via a static import here (the only static import in this file, so
// import sorting can't reorder it) and then importing the server dynamically
// guarantees the correct ordering regardless of launcher (tsx/node) or tooling.
import "./env.js";

await import("./server.js");
