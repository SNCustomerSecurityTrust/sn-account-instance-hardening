# ServiceNow Instance Scan - Scripted Check Reference

## Overview

Instance Scan is a ServiceNow platform capability (introduced in **Paris**, significantly enhanced in **Quebec**) that scans platform objects against defined rules ("checks") to identify configuration issues, bad practices, security gaps, and technical debt. It produces "findings" that can be triaged, assigned, and resolved.

### Scan Types

| Scan Type | Description |
|-----------|-------------|
| **Full Instance Scan** | Runs all active checks against the entire instance |
| **Suite Scan** | Runs only checks in a specific suite |
| **Application Scan** | Scans a specific scoped application |
| **Update Set Scan** | Scans records in a specific update set |
| **Point Scan** | Scans a single record on a table extending `sys_metadata` |
| **Test Scan** | Tests a single scan check |

---

## Check Types

### Table Check

- Scans a **specific table** for records matching defined conditions
- Supports a Condition Builder (visual) or Script field
- Only scans customer updates (not OOB artifacts)
- Available engine properties: `engine.finding`, `engine.current`

```javascript
(function (engine) {
    // engine.current is the GlideRecord of the current record being scanned
    if (someCondition) {
        engine.finding.increment();
    }
})(engine);
```

### Column Type Check

- Scans **all tables** for specific field types: **Script**, **XML**, or **HTML**
- The mandatory Script field evaluates the column content
- Only scans customer updates
- Available engine properties: `engine.finding`, `engine.columnValue`

```javascript
(function (engine) {
    // engine.columnValue contains the full field content
    if (engine.columnValue && engine.columnValue.match(/badPattern/)) {
        engine.finding.increment();
    }
})(engine);
```

### Script Only Check

- No table or column type — runs **arbitrary script logic**
- Can scan both customer updates AND out-of-the-box artifacts
- Must use `finding.setCurrentSource(gr)` to link findings to specific records
- Available engine properties: `engine.finding` only (you query your own GlideRecords)

```javascript
(function (engine) {
    var gr = new GlideRecord('sys_properties');
    gr.addQuery('name', 'some.property.name');
    gr.addQuery('value!=', 'expected_value');
    gr.setLimit(1);
    gr._query();

    if (gr._next()) {
        engine.finding.setCurrentSource(gr);
        engine.finding.increment();
    }
})(engine);
```

### Linter Check (Quebec+)

- The most powerful check type
- Converts script fields into an **Abstract Syntax Tree (AST)** for structural code analysis
- Available engine properties: `engine.rootNode`, `engine.finding`

```javascript
(function (engine) {
    engine.rootNode.visit(function(node) {
        if (node.getNameIdentifier() &&
            node.getTypeName() === 'NAME' &&
            node.getParent().getTypeName() === 'CALL' &&
            node.getNameIdentifier() === 'alert') {
            engine.finding.incrementWithNode(node);
        }
    });
})(engine);
```

---

## The `engine` Object

Introduced in **Quebec** as a unified replacement for the older `finding`, `current`, and `columnValue` parameters. Accessed within an IIFE:

```javascript
(function (engine) {
    // check logic here
})(engine);
```

### Properties by Check Type

| Property | Available In | Description |
|----------|-------------|-------------|
| `engine.finding` | All check types | Primary object for creating and managing findings |
| `engine.current` | Table Check | GlideRecord of the current record being scanned |
| `engine.columnValue` | Column Type Check | Contents of the Script/XML/HTML field being scanned |
| `engine.rootNode` | Linter Check | Root node of the Abstract Syntax Tree |
| `engine.script` | Column Type / Linter | The raw script content as a string |

---

## The `engine.finding` Object

### Methods

| Method | Description |
|--------|-------------|
| `engine.finding.increment()` | Creates a finding or increments the finding count. This is the primary method that tells Instance Scan "we found an issue." |
| `engine.finding.setCurrentSource(glideRecord)` | Sets the source record for the finding. Provides a direct link to the offending record. **Required** for Script Only Checks. |
| `engine.finding.setValue('finding_details', value)` | Populates the "Finding Details" column on the `scan_finding` record. Allows contextual information about what was found. |
| `engine.finding.incrementWithNode(node)` | **Linter checks only.** Records a finding tied to a specific AST node, providing positional information in the script. |

### Usage Pattern

```javascript
// Create a finding linked to a specific record with details
engine.finding.setCurrentSource(gr);
engine.finding.increment();
engine.finding.setValue('finding_details',
    'User: ' + gr.user.name + ' | Role: ' + gr.role.name);
```

Multiple findings can be created per check by calling `increment()` repeatedly with different `setCurrentSource()` and `setValue()` calls.

---

## AST Node Methods (Linter Checks)

### `engine.rootNode` Methods

| Method | Description |
|--------|-------------|
| `engine.rootNode.visit(callback)` | Traverses all nodes in the AST tree, calling the callback for each node |

### Node Methods (within `visit()` callback)

| Method | Description |
|--------|-------------|
| `node.getTypeName()` | Returns the node type (e.g., `SCRIPT`, `CALL`, `NAME`, `STRING`, `BLOCK`, `FUNCTION`, `VAR`, `GETPROP`, `NEW`) |
| `node.getNameIdentifier()` | Returns the name identifier for `NAME`-type nodes (variable names, function names) |
| `node.getParent()` | Returns the parent node in the AST hierarchy |
| `node.getAbsolutePosition()` | Returns the character position from the start of the script |
| `node.debugPrint()` | Outputs a formatted representation of the AST structure (for debugging) |

### Debugging AST Structure

```javascript
(function (engine) {
    engine.rootNode.visit(function(node) {
        if (node.getAbsolutePosition() === 0 &&
            node.getTypeName() === 'SCRIPT') {
            gs.info("AST Structure:\n" + node.debugPrint());
        }
    });
})(engine);
```

---

## Key Tables

### Core Tables

| Table | Label | Description |
|-------|-------|-------------|
| `scan_check` | Scan Check | Check definitions — rules that detect bad practices |
| `scan_finding` | Scan Finding | Violations found by checks |
| `scan_result` | Scan Result | Generated after a scan execution |
| `scan_suite` | Scan Suite | Collections of related checks |
| `scan_task` | Scan Task | Extends `task`; for assignment and resolution tracking |
| `scan_target` | Scan Target | Target definitions for scans |
| `scan_combo` | Scan Combo | Combinations of suite + targets |
| `scan_check_execution` | Check Execution | Per-check execution details within a scan |

### Key Fields on `scan_check`

| Field | Description |
|-------|-------------|
| `name` | Name of the check |
| `short_description` | Brief summary |
| `description` | Detailed description |
| `resolution_details` | How to fix findings (critical for end users) |
| `check_type` | Table Check, Column Type Check, Script Only Check, or Linter Check |
| `category` | Performance, Security, Upgradeability, Manageability, User Experience |
| `script` | The check logic script |
| `run_condition` | Evaluates before execution (e.g., plugin check, environment check) |
| `active` | Enable/disable toggle |
| `table` | Target table (for Table Checks) |

### Key Fields on `scan_finding`

| Field | Description |
|-------|-------------|
| `check` | Reference to the `scan_check` |
| `source_table` | Table containing the offending record |
| `source_record` | sys_id of the offending record |
| `count` | Number of occurrences |
| `finding_details` | Custom details populated via `setValue()` |
| `result` | Reference to the `scan_result` |

### Data Model Relationships

```
scan_suite (collection of checks)
    |
    +-- scan_combo (suite + targets)
    |       |
    |       +-- scan_target (what to scan)
    |
    +-- scan_check (individual check rules)
            |
            +-- scan_check_execution (per-check execution details)
            |
            +-- scan_finding (violations found)
                    |
                    +-- scan_task (extends task; for assignment/resolution)

scan_result (generated per scan execution)
    |
    +-- scan_finding (related findings)
    +-- scan_check_execution (related executions)
```

---

## Categories

| Category | Description |
|----------|-------------|
| **Performance** | System responsiveness, scalability, efficiency (form load times, query efficiency, scripting) |
| **Security** | Vulnerabilities, security best practices, compliance |
| **Upgradeability** | Smooth upgrades — deprecated APIs, core changes, upgrade blockers |
| **Manageability** | Hard-to-maintain configurations, excessive complexity |
| **User Experience** | Configurations that degrade the user experience |

---

## Priority / Severity Levels

| Priority | Description |
|----------|-------------|
| **P1** (Critical) | Must be resolved immediately; blocks release/deployment |
| **P2** (High) | Should be resolved before next deployment cycle |
| **P3** (Medium) | Resolve when resources allow |
| **P4** (Low) | Informational; resolve opportunistically |

Priority is set at the **check** level (`scan_check` record), not dynamically by the script. All findings inherit the check's priority.

---

## Run Conditions

Run conditions evaluate before a check executes. Use these to scope checks to specific environments or prerequisites.

**Production only:**
```javascript
gs.getProperty('sn_appclient.instance_type') == 'production'
```

**Sub-production only:**
```javascript
gs.getProperty('sn_appclient.instance_type') != 'production'
```

**Check if a plugin is installed:**
```javascript
GlidePluginManager.isActive('com.your_plugin.id')
```

---

## Programmatic API (`sn_instance_scan`)

### ScanInstance Class

```javascript
var scan = new sn_instance_scan.ScanInstance();

scan.triggerFullScan();                          // Full instance scan
scan.triggerSuiteScan(suiteId);                  // Suite scan
scan.triggerAppScan(scopeId);                    // Application scan
scan.triggerUpdateSetScan(updatesetId);          // Update set scan
scan.triggerPointScan(tableName, sysId);         // Point scan (single record)
scan.triggerTestScan(scanCheckId);               // Test a single check
scan.triggerScanFromCombo(comboId);              // Scan from combo record
```

### ScanUtil Class

```javascript
var comboId = new sn_instance_scan.ScanUtil()
    .getOrCreateComboFromSuiteAndTargets(suiteId, targetTable, targetIds);
```

### REST APIs (`sn_cicd` namespace)

- `Instance Scan Execute Update Set Scan` (POST)
- `Instance Scan Execute Application Scan` (POST)
- `Instance Scan Execute Point Scan` (POST)
- `Execute scan with suite on scoped apps` (POST)
- `Execute scan with suite on update sets` (POST)

### Flow Designer Spokes

Under "Continuous Integration and Continuous Delivery (CICD) Spoke":
- Instance Scan Execute Point Scan
- Instance Scan Execute Application Scan
- Instance Scan Execute Update Set Scan

---

## Complete Code Examples

### Example 1: Script Only — Validate System Property

```javascript
(function (engine) {
    var gr = new GlideRecord('sys_properties');
    gr.addEncodedQuery('name=glide.ui.goto_use_contains^value!=false');
    gr.setLimit(1);
    gr._query();

    if (gr._next()) {
        engine.finding.setCurrentSource(gr);
        engine.finding.increment();
    }
})(engine);
```

### Example 2: Table Check — Self-Referencing Remote Instance

```javascript
(function (engine) {
    var current_instance = gs.getProperty('glide.servlet.uri').replace(/\/$/, "");
    var remote_instance = engine.current.url.replace(/\/$/, "");

    if (current_instance == remote_instance) {
        engine.finding.increment();
    }
})(engine);
```

### Example 3: Script Only — Inactive Users with Active Roles

```javascript
(function (engine) {
    var gr = new GlideRecord('sys_user_has_role');
    gr.addQuery('role.name', 'admin');
    gr.addQuery('user.active', false);
    gr._query();

    while (gr._next()) {
        engine.finding.setCurrentSource(gr);
        engine.finding.increment();
        engine.finding.setValue('finding_details',
            'User: ' + gr.user.name +
            ' | Role: ' + gr.role.name +
            ' | Active: ' + gr.user.active);
    }
})(engine);
```

### Example 4: Linter — Detect Debug Statements

```javascript
(function (engine) {
    var debugMethods = ['log', 'debug', 'print'];
    var debugObjects = ['gs', 'console'];

    engine.rootNode.visit(function(node) {
        if (node.getTypeName() === 'GETPROP') {
            var children = [];
            node.visit(function(child) {
                children.push(child);
            });
            var hasObject = false;
            var hasMethod = false;
            for (var i = 0; i < children.length; i++) {
                var id = children[i].getNameIdentifier();
                if (id && debugObjects.indexOf(id) > -1) hasObject = true;
                if (id && debugMethods.indexOf(id) > -1) hasMethod = true;
            }
            if (hasObject && hasMethod) {
                engine.finding.incrementWithNode(node);
            }
        }
    });
})(engine);
```

### Example 5: Linter — Detect `new Object()` Anti-Pattern

```javascript
(function (engine) {
    engine.rootNode.visit(function(node) {
        if (node.getTypeName() === 'NAME' &&
            node.getNameIdentifier() === 'Object' &&
            node.getParent() &&
            node.getParent().getTypeName() === 'NEW') {
            engine.finding.incrementWithNode(node);
        }
    });
})(engine);
```

### Example 6: Script Only — Orphaned Attachments

```javascript
(function (engine) {
    var gr = new GlideRecord('sys_attachment');
    gr.addEncodedQuery('table_nameNOT LIKEinvisible.^table_name!=NULL^table_sys_id!=NULL');
    gr._query();

    while (gr._next()) {
        if (gs.tableExists(gr.table_name.replace('ZZ_YY', ''))) {
            var validate = new GlideRecord(gr.table_name.replace('ZZ_YY', ''));
            validate.addQuery('sys_id', gr.table_sys_id);
            validate.setLimit(1);
            validate._query();

            if (!validate.hasNext()) {
                engine.finding.setCurrentSource(gr);
                engine.finding.increment();
            }
        }
    }
})(engine);
```

---

## Best Practices

### Performance

- **Timeout limit**: Individual checks timeout after **10 minutes** by default (`glide.scan.process_check.time_out`, value in seconds). This property must be added manually.
- Use `setLimit(1)` when checking for record existence
- Use `_query()` and `_next()` (underscore-prefixed) to avoid triggering business rules on queried records
- Narrow queries with conditions to reduce datasets before looping
- Use **Run Condition** instead of Script for environment checks — avoids running the check and reporting zero findings, which skews scoring

### Governance

- Write thorough **descriptions** and **resolution details** for all checks
- Make scanning part of sprint/release checklists
- Schedule regular full scans (recommended: every 4 weeks)
- Use Run Conditions to target checks to specific environments or plugin dependencies
- Create tasks from findings for triage and resolution tracking

### Limitations

- OOB scan checks are **read-only** — cannot be modified or deactivated
- The AST parser (Rhino-based) struggles with modern JavaScript syntax (ES12+)
- When checking `node.getParent()` in Linter checks, validate the parent is not null first
- Very limited official documentation — community resources and OOB examples are the primary references

---

## Sources

- [How to implement the instance scan process](https://www.servicenow.com/community/servicenow-ai-platform-articles/how-to-implement-the-instance-scan-process/ta-p/3261493)
- [How to use the engine object in Instance Scan scripting](https://www.servicenow.com/community/developer-articles/how-to-use-the-engine-object-in-instance-scan-scripting/ta-p/2300983)
- [Instance scan continued - Useful methods for Script Only Checks](https://www.servicenow.com/community/servicenow-ai-platform-blog/instance-scan-continued-useful-methods-for-script-only-checks/ba-p/3251872)
- [Creating your own Instance Scan, Scan Checks](https://www.servicenow.com/community/developer-blog/creating-your-own-instance-scan-scan-checks/ba-p/2278735)
- [Instance Scan data model (San Diego)](https://www.servicenow.com/community/developer-articles/instance-scan-data-model-san-diego/ta-p/2296685)
- [Instance Scan Core Configuration examples](https://www.servicenow.com/community/developer-articles/instance-scan-quot-core-configuration-quot-scan-check-examples/ta-p/2296515)
- [Instance Scan Linter Check examples](https://www.servicenow.com/community/developer-articles/instance-scan-linter-check-examples/ta-p/2306612)
- [Demystifying Instance Scan - Linter Check](https://www.servicenow.com/community/servicenow-ai-platform-articles/demystifying-instance-scan-linter-check/ta-p/2312466)
- [Unrevealing Instance Scan - undocumented parts](https://www.servicenow.com/community/developer-blog/unrevealing-instance-scan-and-sharing-parts-of-the-undocumented/ba-p/2292017)
- [Automating Instance Scan APIs and Spokes](https://www.servicenow.com/community/developer-articles/automating-instance-scan-api-s-spokes/ta-p/2304350)
- [GitHub - ServiceNowDevProgram/example-instancescan-checks](https://github.com/ServiceNowDevProgram/example-instancescan-checks)
