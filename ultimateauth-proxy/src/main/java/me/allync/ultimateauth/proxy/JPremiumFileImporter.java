package me.allync.ultimateauth.proxy;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

final class JPremiumFileImporter {
    private static final String FILE_IMPORT_META_KEY = "jpremium_file_import_completed_at";

    private final UltimateAuthPlugin plugin;
    private final DatabaseManager database;
    private final PluginConfig config;

    JPremiumFileImporter(UltimateAuthPlugin plugin, DatabaseManager database, PluginConfig config) {
        this.plugin = plugin;
        this.database = database;
        this.config = config;
    }

    void importIfNeeded() throws SQLException {
        PluginConfig.FileImport fileImport = config.migration().fileImport();
        if (!fileImport.enabled()) {
            return;
        }
        if (fileImport.runOnce() && database.loadMeta(FILE_IMPORT_META_KEY).isPresent()) {
            return;
        }

        File directory = new File(plugin.getDataFolder(), fileImport.directory());
        if (!directory.exists() && !directory.mkdirs()) {
            plugin.getLogger().warning("UltimateAuth could not create import directory: " + directory.getAbsolutePath());
            return;
        }

        Optional<File> sourceFile = resolveSourceFile(directory, fileImport.fileName());
        if (sourceFile.isEmpty()) {
            return;
        }

        File file = sourceFile.get();
        int imported;
        try {
            imported = isSqliteFile(file)
                    ? importFromSqliteFile(file)
                    : importFromSqlDump(file);
        } catch (IOException exception) {
            throw new SQLException("Unable to read import file '" + file.getName() + "': " + exception.getMessage(), exception);
        }

        if (imported <= 0) {
            plugin.getLogger().warning("UltimateAuth found no importable accounts in file '" + file.getName() + "'.");
            return;
        }

        if (fileImport.runOnce()) {
            database.saveMeta(FILE_IMPORT_META_KEY, String.valueOf(System.currentTimeMillis()));
            database.saveMeta("jpremium_file_import_name", file.getName());
        }
        plugin.getLogger().info("UltimateAuth imported " + imported + " account(s) from file '" + file.getName() + "'.");
    }

    private Optional<File> resolveSourceFile(File directory, String configuredFileName) {
        if (configuredFileName != null && !configuredFileName.isBlank()) {
            File file = new File(directory, configuredFileName);
            if (!file.isFile()) {
                plugin.getLogger().warning("Configured import file was not found: " + file.getAbsolutePath());
                return Optional.empty();
            }
            if (!isSupported(file)) {
                plugin.getLogger().warning("Configured import file has unsupported extension: " + file.getName());
                return Optional.empty();
            }
            return Optional.of(file);
        }

        File[] files = directory.listFiles(pathname -> pathname.isFile() && isSupported(pathname));
        if (files == null || files.length == 0) {
            plugin.getLogger().info("UltimateAuth import directory is empty: " + directory.getAbsolutePath());
            return Optional.empty();
        }

        List<File> supportedFiles = new ArrayList<>(List.of(files));
        supportedFiles.sort(Comparator.comparing(File::getName, String.CASE_INSENSITIVE_ORDER));
        if (supportedFiles.size() > 1) {
            plugin.getLogger().warning("UltimateAuth found multiple import files. Set migration.jpremium.fileImport.fileName to choose one.");
            return Optional.empty();
        }
        return Optional.of(supportedFiles.getFirst());
    }

    private int importFromSqliteFile(File file) throws SQLException {
        PluginConfig.Migration migration = config.migration();
        String jdbcUrl = "jdbc:sqlite:" + file.getAbsolutePath();

        try (Connection connection = DriverManager.getConnection(jdbcUrl)) {
            if (!tableExists(connection, migration.sourceTable())) {
                plugin.getLogger().warning("SQLite import skipped because table '" + migration.sourceTable() + "' was not found in " + file.getName());
                return 0;
            }

            String sql = "SELECT "
                    + sqliteIdentifier(migration.columns().username()) + ", "
                    + sqliteIdentifier(migration.columns().uniqueId()) + ", "
                    + sqliteIdentifier(migration.columns().premiumUniqueId()) + ", "
                    + sqliteIdentifier(migration.columns().passwordHash()) + ", "
                    + sqliteIdentifier(migration.columns().premium()) + ", "
                    + sqliteIdentifier(migration.columns().lastIp()) + ", "
                    + sqliteIdentifier(migration.columns().lastSeen())
                    + " FROM " + sqliteIdentifier(migration.sourceTable());

            int imported = 0;
            try (PreparedStatement statement = connection.prepareStatement(sql);
                 ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    imported += database.importAccount(new ImportedAccountData(
                            resultSet.getString(migration.columns().username()),
                            resultSet.getString(migration.columns().uniqueId()),
                            resultSet.getString(migration.columns().premiumUniqueId()),
                            resultSet.getString(migration.columns().passwordHash()),
                            resultSet.getObject(migration.columns().premium()),
                            resultSet.getString(migration.columns().lastIp()),
                            resultSet.getObject(migration.columns().lastSeen())
                    ), migration.defaultPasswordAlgorithm());
                }
            }
            return imported;
        }
    }

    private int importFromSqlDump(File file) throws IOException {
        PluginConfig.Migration migration = config.migration();
        String cleanedSql = stripComments(Files.readString(file.toPath(), StandardCharsets.UTF_8));
        List<String> statements = splitSqlStatements(cleanedSql);

        List<String> discoveredColumns = List.of();
        int imported = 0;
        for (String statement : statements) {
            String trimmed = statement.trim();
            if (trimmed.isEmpty()) {
                continue;
            }

            Optional<List<String>> createColumns = parseCreateTableColumns(trimmed, migration.sourceTable());
            if (createColumns.isPresent()) {
                discoveredColumns = createColumns.get();
                continue;
            }

            Optional<ParsedInsert> parsedInsert = parseInsertStatement(trimmed, migration.sourceTable(), discoveredColumns);
            if (parsedInsert.isEmpty()) {
                continue;
            }

            for (List<String> row : parsedInsert.get().rows()) {
                imported += database.importAccount(new ImportedAccountData(
                        valueFor(parsedInsert.get().columns(), row, migration.columns().username()),
                        valueFor(parsedInsert.get().columns(), row, migration.columns().uniqueId()),
                        valueFor(parsedInsert.get().columns(), row, migration.columns().premiumUniqueId()),
                        valueFor(parsedInsert.get().columns(), row, migration.columns().passwordHash()),
                        valueFor(parsedInsert.get().columns(), row, migration.columns().premium()),
                        valueFor(parsedInsert.get().columns(), row, migration.columns().lastIp()),
                        valueFor(parsedInsert.get().columns(), row, migration.columns().lastSeen())
                ), migration.defaultPasswordAlgorithm());
            }
        }
        return imported;
    }

    private Optional<List<String>> parseCreateTableColumns(String statement, String sourceTable) {
        int tableKeywordIndex = indexOfKeywordOutsideQuotes(statement, "TABLE", 0);
        if (tableKeywordIndex < 0) {
            return Optional.empty();
        }

        int index = tableKeywordIndex + "TABLE".length();
        index = skipWhitespace(statement, index);
        if (statement.regionMatches(true, index, "IF NOT EXISTS", 0, "IF NOT EXISTS".length())) {
            index += "IF NOT EXISTS".length();
        }
        index = skipWhitespace(statement, index);

        ParseResult tableResult = parseQualifiedIdentifier(statement, index);
        if (tableResult == null || !tableResult.identifier().equalsIgnoreCase(sourceTable)) {
            return Optional.empty();
        }

        int openParenthesis = statement.indexOf('(', tableResult.nextIndex());
        if (openParenthesis < 0) {
            return Optional.empty();
        }
        int closeParenthesis = findMatchingParenthesis(statement, openParenthesis);
        if (closeParenthesis < 0) {
            return Optional.empty();
        }

        List<String> columns = new ArrayList<>();
        for (String part : splitTopLevel(statement.substring(openParenthesis + 1, closeParenthesis), ',')) {
            String trimmed = part.trim();
            if (trimmed.isEmpty()) {
                continue;
            }

            String upper = trimmed.toUpperCase(Locale.ROOT);
            if (upper.startsWith("PRIMARY KEY") || upper.startsWith("UNIQUE")
                    || upper.startsWith("KEY ") || upper.startsWith("INDEX ")
                    || upper.startsWith("CONSTRAINT") || upper.startsWith("FOREIGN KEY")
                    || upper.startsWith("CHECK")) {
                continue;
            }

            ParseResult columnResult = parseQualifiedIdentifier(trimmed, 0);
            if (columnResult != null) {
                columns.add(columnResult.identifier());
            }
        }
        return columns.isEmpty() ? Optional.empty() : Optional.of(columns);
    }

    private Optional<ParsedInsert> parseInsertStatement(String statement, String sourceTable, List<String> fallbackColumns) {
        int intoIndex;
        if (startsWithKeyword(statement, "INSERT")) {
            intoIndex = indexOfKeywordOutsideQuotes(statement, "INTO", 0);
        } else if (startsWithKeyword(statement, "REPLACE")) {
            intoIndex = indexOfKeywordOutsideQuotes(statement, "INTO", 0);
        } else {
            return Optional.empty();
        }
        if (intoIndex < 0) {
            return Optional.empty();
        }

        int index = skipWhitespace(statement, intoIndex + "INTO".length());
        ParseResult tableResult = parseQualifiedIdentifier(statement, index);
        if (tableResult == null || !tableResult.identifier().equalsIgnoreCase(sourceTable)) {
            return Optional.empty();
        }

        index = skipWhitespace(statement, tableResult.nextIndex());
        List<String> columns = fallbackColumns;
        if (index < statement.length() && statement.charAt(index) == '(') {
            int close = findMatchingParenthesis(statement, index);
            if (close < 0) {
                return Optional.empty();
            }
            columns = parseIdentifierList(statement.substring(index + 1, close));
            index = close + 1;
        }
        if (columns == null || columns.isEmpty()) {
            return Optional.empty();
        }

        int valuesIndex = indexOfKeywordOutsideQuotes(statement, "VALUES", index);
        if (valuesIndex < 0) {
            return Optional.empty();
        }

        List<List<String>> rows = new ArrayList<>();
        String valuesSection = statement.substring(valuesIndex + "VALUES".length());
        int cursor = 0;
        while (cursor < valuesSection.length()) {
            while (cursor < valuesSection.length()
                    && (Character.isWhitespace(valuesSection.charAt(cursor)) || valuesSection.charAt(cursor) == ',')) {
                cursor++;
            }
            if (cursor >= valuesSection.length() || valuesSection.charAt(cursor) != '(') {
                break;
            }

            int close = findMatchingParenthesis(valuesSection, cursor);
            if (close < 0) {
                break;
            }

            List<String> row = parseValueList(valuesSection.substring(cursor + 1, close));
            if (row.size() == columns.size()) {
                rows.add(row);
            }
            cursor = close + 1;
        }

        return rows.isEmpty() ? Optional.empty() : Optional.of(new ParsedInsert(columns, rows));
    }

    private List<String> parseIdentifierList(String text) {
        List<String> identifiers = new ArrayList<>();
        for (String part : splitTopLevel(text, ',')) {
            ParseResult parsed = parseQualifiedIdentifier(part.trim(), 0);
            if (parsed != null) {
                identifiers.add(parsed.identifier());
            }
        }
        return identifiers;
    }

    private List<String> parseValueList(String text) {
        List<String> values = new ArrayList<>();
        for (String part : splitTopLevel(text, ',')) {
            values.add(parseSqlLiteral(part.trim()));
        }
        return values;
    }

    private String parseSqlLiteral(String token) {
        if (token.isEmpty()) {
            return "";
        }

        if (token.equalsIgnoreCase("NULL")) {
            return null;
        }
        if ((token.startsWith("'") && token.endsWith("'")) || (token.startsWith("\"") && token.endsWith("\""))) {
            return unescapeSqlString(token.substring(1, token.length() - 1), token.charAt(0));
        }
        return token;
    }

    private String unescapeSqlString(String value, char quote) {
        StringBuilder builder = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);

            if (current == '\\' && index + 1 < value.length()) {
                char next = value.charAt(++index);
                switch (next) {
                    case 'n' -> builder.append('\n');
                    case 'r' -> builder.append('\r');
                    case 't' -> builder.append('\t');
                    case '\\' -> builder.append('\\');
                    case '\'' -> builder.append('\'');
                    case '"' -> builder.append('"');
                    case '0' -> builder.append('\0');
                    default -> builder.append(next);
                }
                continue;
            }

            if (current == quote && index + 1 < value.length() && value.charAt(index + 1) == quote) {
                builder.append(quote);
                index++;
                continue;
            }
            builder.append(current);
        }
        return builder.toString();
    }

    private List<String> splitSqlStatements(String text) {
        List<String> statements = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;
        boolean inBacktick = false;

        for (int index = 0; index < text.length(); index++) {
            char character = text.charAt(index);

            if (character == '\'' && !inDoubleQuote && !inBacktick && !isEscaped(text, index)) {
                inSingleQuote = !inSingleQuote;
            } else if (character == '"' && !inSingleQuote && !inBacktick && !isEscaped(text, index)) {
                inDoubleQuote = !inDoubleQuote;
            } else if (character == '`' && !inSingleQuote && !inDoubleQuote) {
                inBacktick = !inBacktick;
            }

            if (character == ';' && !inSingleQuote && !inDoubleQuote && !inBacktick) {
                statements.add(current.toString());
                current.setLength(0);
                continue;
            }
            current.append(character);
        }

        if (!current.isEmpty()) {
            statements.add(current.toString());
        }
        return statements;
    }

    private String stripComments(String text) {
        StringBuilder cleaned = new StringBuilder(text.length());
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;
        boolean inBacktick = false;

        for (int index = 0; index < text.length(); index++) {
            char current = text.charAt(index);

            if (!inSingleQuote && !inDoubleQuote && !inBacktick) {
                if (current == '-' && index + 1 < text.length() && text.charAt(index + 1) == '-') {
                    index += 2;
                    while (index < text.length() && text.charAt(index) != '\n') {
                        index++;
                    }
                    if (index < text.length()) {
                        cleaned.append('\n');
                    }
                    continue;
                }
                if (current == '#') {
                    while (index < text.length() && text.charAt(index) != '\n') {
                        index++;
                    }
                    if (index < text.length()) {
                        cleaned.append('\n');
                    }
                    continue;
                }
                if (current == '/' && index + 1 < text.length() && text.charAt(index + 1) == '*') {
                    index += 2;
                    while (index + 1 < text.length() && !(text.charAt(index) == '*' && text.charAt(index + 1) == '/')) {
                        index++;
                    }
                    index++;
                    continue;
                }
            }

            if (current == '\'' && !inDoubleQuote && !inBacktick && !isEscaped(text, index)) {
                inSingleQuote = !inSingleQuote;
            } else if (current == '"' && !inSingleQuote && !inBacktick && !isEscaped(text, index)) {
                inDoubleQuote = !inDoubleQuote;
            } else if (current == '`' && !inSingleQuote && !inDoubleQuote) {
                inBacktick = !inBacktick;
            }

            cleaned.append(current);
        }
        return cleaned.toString();
    }

    private List<String> splitTopLevel(String text, char delimiter) {
        List<String> parts = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;
        boolean inBacktick = false;
        int parenthesesDepth = 0;

        for (int index = 0; index < text.length(); index++) {
            char character = text.charAt(index);

            if (character == '\'' && !inDoubleQuote && !inBacktick && !isEscaped(text, index)) {
                inSingleQuote = !inSingleQuote;
            } else if (character == '"' && !inSingleQuote && !inBacktick && !isEscaped(text, index)) {
                inDoubleQuote = !inDoubleQuote;
            } else if (character == '`' && !inSingleQuote && !inDoubleQuote) {
                inBacktick = !inBacktick;
            } else if (!inSingleQuote && !inDoubleQuote && !inBacktick) {
                if (character == '(') {
                    parenthesesDepth++;
                } else if (character == ')' && parenthesesDepth > 0) {
                    parenthesesDepth--;
                }
            }

            if (character == delimiter && !inSingleQuote && !inDoubleQuote && !inBacktick && parenthesesDepth == 0) {
                parts.add(current.toString());
                current.setLength(0);
                continue;
            }
            current.append(character);
        }

        if (!current.isEmpty()) {
            parts.add(current.toString());
        }
        return parts;
    }

    private int indexOfKeywordOutsideQuotes(String text, String keyword, int fromIndex) {
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;
        boolean inBacktick = false;

        for (int index = fromIndex; index <= text.length() - keyword.length(); index++) {
            char character = text.charAt(index);
            if (character == '\'' && !inDoubleQuote && !inBacktick && !isEscaped(text, index)) {
                inSingleQuote = !inSingleQuote;
            } else if (character == '"' && !inSingleQuote && !inBacktick && !isEscaped(text, index)) {
                inDoubleQuote = !inDoubleQuote;
            } else if (character == '`' && !inSingleQuote && !inDoubleQuote) {
                inBacktick = !inBacktick;
            }

            if (inSingleQuote || inDoubleQuote || inBacktick) {
                continue;
            }

            if (text.regionMatches(true, index, keyword, 0, keyword.length())) {
                boolean leftOk = index == 0 || !Character.isLetterOrDigit(text.charAt(index - 1));
                boolean rightOk = index + keyword.length() >= text.length()
                        || !Character.isLetterOrDigit(text.charAt(index + keyword.length()));
                if (leftOk && rightOk) {
                    return index;
                }
            }
        }
        return -1;
    }

    private int findMatchingParenthesis(String text, int openIndex) {
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;
        boolean inBacktick = false;
        int depth = 0;

        for (int index = openIndex; index < text.length(); index++) {
            char character = text.charAt(index);
            if (character == '\'' && !inDoubleQuote && !inBacktick && !isEscaped(text, index)) {
                inSingleQuote = !inSingleQuote;
            } else if (character == '"' && !inSingleQuote && !inBacktick && !isEscaped(text, index)) {
                inDoubleQuote = !inDoubleQuote;
            } else if (character == '`' && !inSingleQuote && !inDoubleQuote) {
                inBacktick = !inBacktick;
            }

            if (inSingleQuote || inDoubleQuote || inBacktick) {
                continue;
            }

            if (character == '(') {
                depth++;
            } else if (character == ')') {
                depth--;
                if (depth == 0) {
                    return index;
                }
            }
        }
        return -1;
    }

    private ParseResult parseQualifiedIdentifier(String text, int startIndex) {
        int index = skipWhitespace(text, startIndex);
        List<String> parts = new ArrayList<>();

        while (index < text.length()) {
            ParseResult segment = parseIdentifierSegment(text, index);
            if (segment == null) {
                break;
            }
            parts.add(segment.identifier());
            index = skipWhitespace(text, segment.nextIndex());
            if (index < text.length() && text.charAt(index) == '.') {
                index = skipWhitespace(text, index + 1);
                continue;
            }
            return new ParseResult(parts.get(parts.size() - 1), index);
        }
        return null;
    }

    private ParseResult parseIdentifierSegment(String text, int startIndex) {
        int index = skipWhitespace(text, startIndex);
        if (index >= text.length()) {
            return null;
        }

        char opening = text.charAt(index);
        if (opening == '`' || opening == '"' || opening == '[') {
            char closing = opening == '[' ? ']' : opening;
            int end = index + 1;
            while (end < text.length() && text.charAt(end) != closing) {
                end++;
            }
            if (end >= text.length()) {
                return null;
            }
            return new ParseResult(text.substring(index + 1, end), end + 1);
        }

        int end = index;
        while (end < text.length()) {
            char current = text.charAt(end);
            if (Character.isWhitespace(current) || current == ',' || current == '(' || current == ')' || current == '.') {
                break;
            }
            end++;
        }
        if (end == index) {
            return null;
        }
        return new ParseResult(text.substring(index, end), end);
    }

    private int skipWhitespace(String text, int startIndex) {
        int index = startIndex;
        while (index < text.length() && Character.isWhitespace(text.charAt(index))) {
            index++;
        }
        return index;
    }

    private boolean startsWithKeyword(String statement, String keyword) {
        int index = skipWhitespace(statement, 0);
        return statement.regionMatches(true, index, keyword, 0, keyword.length());
    }

    private boolean isEscaped(String text, int index) {
        int slashCount = 0;
        for (int current = index - 1; current >= 0 && text.charAt(current) == '\\'; current--) {
            slashCount++;
        }
        return slashCount % 2 != 0;
    }

    private String valueFor(List<String> columns, List<String> row, String targetColumn) {
        for (int index = 0; index < columns.size() && index < row.size(); index++) {
            if (columns.get(index) != null && targetColumn != null && columns.get(index).equalsIgnoreCase(targetColumn)) {
                return row.get(index);
            }
        }
        return null;
    }

    private boolean tableExists(Connection connection, String tableName) throws SQLException {
        DatabaseMetaData metaData = connection.getMetaData();
        try (ResultSet resultSet = metaData.getTables(null, null, tableName, new String[]{"TABLE"})) {
            return resultSet.next();
        }
    }

    private String sqliteIdentifier(String value) {
        return "\"" + value.replace("\"", "\"\"") + "\"";
    }

    private boolean isSupported(File file) {
        String lower = file.getName().toLowerCase(Locale.ROOT);
        return lower.endsWith(".db") || lower.endsWith(".sqlite") || lower.endsWith(".sqlite3") || lower.endsWith(".sql");
    }

    private boolean isSqliteFile(File file) {
        String lower = file.getName().toLowerCase(Locale.ROOT);
        return lower.endsWith(".db") || lower.endsWith(".sqlite") || lower.endsWith(".sqlite3");
    }

    private record ParseResult(String identifier, int nextIndex) {
    }

    private record ParsedInsert(List<String> columns, List<List<String>> rows) {
    }
}
