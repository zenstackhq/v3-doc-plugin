import { OnKyselyQueryCallback, RuntimePlugin } from "@zenstackhq/orm";
import {
  CallExpression,
  ExpressionUtils,
  SchemaDef,
} from "@zenstackhq/orm/schema";
import bcrypt from "bcryptjs";
import type { QueryId } from "kysely";
import {
  ColumnNode,
  ColumnUpdateNode,
  InsertQueryNode,
  OperationNodeTransformer,
  PrimitiveValueListNode,
  TableNode,
  UpdateQueryNode,
  ValueListNode,
  ValueNode,
  ValuesNode,
  type OperationNode,
} from "kysely";

/**
 * Kysely query transformer that hashes field values for insert and update nodes
 */
class PasswordHasherTransformer extends OperationNodeTransformer {
  constructor(private readonly schema: SchemaDef) {
    super();
  }

  protected override transformInsertQuery(
    node: InsertQueryNode,
    queryId?: QueryId
  ) {
    if (!node.into || !node.columns || !node.values) {
      return super.transformInsertQuery(node, queryId);
    }

    const modelName = this.extractTableName(node.into);
    if (!modelName) {
      return super.transformInsertQuery(node, queryId);
    }

    const transformedValues = this.transformInsertValues(
      modelName,
      node.columns,
      node.values
    );

    const baseResult = super.transformInsertQuery(node, queryId);

    return {
      ...baseResult,
      values: transformedValues,
    };
  }

  private transformInsertValues(
    modelName: string,
    columns: readonly ColumnNode[],
    values: OperationNode
  ): OperationNode {
    if (!ValuesNode.is(values)) {
      return values;
    }

    const transformedValueLists = values.values.map((valueList) => {
      // Handle PrimitiveValueListNode (contains raw primitive values)
      if (PrimitiveValueListNode.is(valueList)) {
        const transformedValues = valueList.values.map((value, index) => {
          const fieldName = columns[index].column.name;
          if (!this.isPasswordField(modelName, fieldName)) {
            return value;
          }
          const hashFn = this.getPasswordHasher(modelName, fieldName);
          return hashFn(value);
        });
        return PrimitiveValueListNode.create(transformedValues);
      }

      // Handle ValueListNode (contains a list of ValueNode)
      if (ValueListNode.is(valueList)) {
        const transformedValues = valueList.values.map((valueNode, index) => {
          const colNode = columns[index];
          if (!ColumnNode.is(colNode)) {
            return valueNode;
          }
          const fieldName = colNode.column.name;
          const hashFn = this.getPasswordHasher(modelName, fieldName);
          return this.transformPasswordValue(valueNode, hashFn);
        });

        return ValueListNode.create(transformedValues);
      }

      return valueList;
    });

    return ValuesNode.create(transformedValueLists);
  }

  protected override transformUpdateQuery(
    node: UpdateQueryNode,
    queryId?: QueryId
  ) {
    if (!node.table || !node.updates) {
      return super.transformUpdateQuery(node, queryId);
    }

    const modelName = this.extractTableName(node.table);
    if (!modelName) {
      return super.transformUpdateQuery(node, queryId);
    }

    const baseResult = super.transformUpdateQuery(node, queryId);

    const transformedUpdates = baseResult.updates?.map((update) => {
      if (!ColumnNode.is(update.column)) {
        return update;
      }

      const columnName = update.column.column.name;
      if (!this.isPasswordField(modelName, columnName)) {
        return update;
      }
      const hashFn = this.getPasswordHasher(modelName, columnName);
      const hashedValue = this.transformPasswordValue(update.value, hashFn);
      return ColumnUpdateNode.create(update.column, hashedValue);
    });

    return UpdateQueryNode.cloneWithUpdates(
      baseResult,
      transformedUpdates ?? []
    );
  }

  private transformPasswordValue(
    node: OperationNode,
    hashFn: (value: unknown) => unknown
  ) {
    if (!ValueNode.is(node)) {
      return node;
    }
    return ValueNode.create(hashFn(node.value));
  }

  private extractTableName(tableNode: OperationNode | undefined) {
    if (!tableNode || !TableNode.is(tableNode)) {
      return undefined;
    }
    return tableNode.table.identifier.name;
  }

  private isPasswordField(modelName: string, fieldName: string): boolean {
    const modelDef = this.schema.models[modelName];
    if (!modelDef) {
      return false;
    }

    const fieldDef = modelDef.fields[fieldName];
    if (!fieldDef) {
      return false;
    }

    return (
      fieldDef.attributes?.some((attr) => attr.name === "@password") ?? false
    );
  }

  private getPasswordHasher(modelName: string, fieldName: string) {
    const modelDef = this.schema.models[modelName]!;
    const fieldDef = modelDef.fields[fieldName]!;

    const passwordAttr = fieldDef.attributes?.find(
      (attr) => attr.name === "@password"
    )!;
    if (!passwordAttr) {
      throw new Error(
        `Field ${modelName}.${fieldName} is not a password field.`
      );
    }

    // Extract the hasher argument
    const hasherArg = passwordAttr.args?.find((arg) => arg.name === "hasher")!;

    // Extract hasher function name
    const hasherExpr = hasherArg.value as CallExpression;
    const hasherName = hasherExpr.function;

    if (hasherName !== "bcryptHasher") {
      throw new Error(`Hasher "${hasherName}" is not implemented.`);
    }

    // Extract salt rounds (default to 10 if not provided)
    let saltRounds = 10;
    const roundsArg = hasherExpr.args?.[0];
    if (
      ExpressionUtils.isLiteral(roundsArg) &&
      typeof roundsArg.value === "number"
    ) {
      saltRounds = roundsArg.value;
    }

    // Return a hashing function
    return (value: unknown) => {
      if (typeof value !== "string") {
        return value;
      }
      return bcrypt.hashSync(value, saltRounds);
    };
  }
}

export class PasswordHasherPlugin<Schema extends SchemaDef = SchemaDef>
  implements RuntimePlugin<Schema>
{
  id = "password-hasher";

  onKyselyQuery: OnKyselyQueryCallback<Schema> = async (args) => {
    // transform the query and hash password fields
    const transformer = new PasswordHasherTransformer(args.schema);
    const transformedQuery = transformer.transformNode(args.query);

    // proceed with the transformed query
    return args.proceed(transformedQuery);
  };
}
