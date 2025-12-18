import type { CliPlugin } from "@zenstackhq/sdk";
import { InvocationExpr, isDataModel } from "@zenstackhq/sdk/ast";
import fs from "node:fs";

const cliPlugin: CliPlugin = {
  name: "Password Report",

  generate: ({ model, defaultOutputPath, pluginOptions }) => {
    // `pluginOptions` contains options defined in the `plugin` block in ZModel
    if (pluginOptions["report"] !== true) {
      // no report requested
      return;
    }

    let output = "# Password Fields Report\n\n";

    for (const dm of model.declarations.filter(isDataModel)) {
      for (const field of dm.fields) {
        const passwordAttr = field.attributes.find(
          (attr) => attr.decl.$refText === "@password"
        );
        if (passwordAttr) {
          const hasherArg = passwordAttr.args.find(
            (arg) => arg.$resolvedParam.name === "hasher"
          );
          const hasherName = hasherArg?.value
            ? (hasherArg.value as InvocationExpr).function.$refText
            : "undefined";
          output += `- **${dm.name}.${field.name}**: hasher "${hasherName}"\n`;
        }
      }
    }

    fs.writeFileSync(
      `${defaultOutputPath}/password-fields.md`,
      output,
      "utf-8"
    );
  },
};

export default cliPlugin;
