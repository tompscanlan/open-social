"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createDb = createDb;
var kysely_1 = require("kysely");
var pg_1 = require("pg");
function createDb(connectionString) {
    return new kysely_1.Kysely({
        dialect: new kysely_1.PostgresDialect({
            pool: new pg_1.Pool({
                connectionString: connectionString,
            }),
        }),
    });
}
