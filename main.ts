import { ZenStackClient } from "@zenstackhq/orm";
import { SqliteDialect } from "@zenstackhq/orm/dialects/sqlite";
import SQLite from "better-sqlite3";
import { schema } from "./zenstack/schema";
import { PasswordHasherPlugin } from "./password-hasher-plugin";

async function main() {
  const db = new ZenStackClient(schema, {
    dialect: new SqliteDialect({
      database: new SQLite("./zenstack/dev.db"),
    }),
    plugins: [new PasswordHasherPlugin()],
  });

  await db.user.deleteMany();

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
