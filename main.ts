import { ZenStackClient } from "@zenstackhq/orm";
import { SqlJsDialect } from "@zenstackhq/orm/dialects/sql.js";
import initSqlJs from "sql.js";
import { PasswordHasherPlugin } from "./password-hasher-plugin";
import { schema } from "./zenstack/schema";

async function main() {
  const SQL = await initSqlJs();

  const db = new ZenStackClient(schema, {
    dialect: new SqlJsDialect({ sqlJs: new SQL.Database() }),
    plugins: [new PasswordHasherPlugin()],
  });

  // push database schema
  await db.$pushSchema();

  console.log("Creating user with plain text password...");
  const user = await db.user.create({
    data: {
      email: "test@zenstack.dev",
      password: "abc123",
    },
  });
  console.log("User created:", user);

  console.log("\nUpdating user password...");
  const updatedUser = await db.user.update({
    where: { id: user.id },
    data: { password: "def456" },
  });

  console.log("Updated user:", updatedUser);
}

main();
