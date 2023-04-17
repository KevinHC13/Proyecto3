import sys
import re
import sqlite3
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLineEdit, QLabel, QPushButton, QTableWidget, QTableWidgetItem
from PyQt5.QtCore import Qt

class SemanticError(Exception):
    pass

class LexicalError(Exception):
    pass

class TokenNoReconocidoError(Exception):
    def __init__(self, message, error_position):
        self.message = message
        self.error_position = error_position

    def __str__(self):
        return f"Error léxico: {self.message} en la posición {self.error_position}."

class Lexico:
    def __init__(self, token_type, value):
        self.token_type = token_type
        self.value = value

    def __str__(self):
        return (f"{self.token_type}: {self.value}")


class SyntaxError(Exception):
    pass

class TableError(Exception):
    def __init__(self, message, original_exception=None):
        super().__init__(message)
        self.original_exception = original_exception

class FormatoLexico:
    def lex(sql):
        tokens = []
        sql = sql.strip().lower()


        forbidden_chars = ["%", "$"]
        if any(char in sql for char in forbidden_chars):
            raise LexicalError(f"Caracter no permitido en el SQL.")

        # Definir los patrones de los tokens
        token_patterns = [
            ("SELECT", r"(?i)select\b"),
            ("INSERT", r"(?i)insert\b"),
            ("UPDATE", r"(?i)update\b"),
            ("DELETE", r"(?i)delete\b"),
            ("FROM", r"(?i)from\b"),
            ("WHERE", r"(?i)where\b"),
            ("AND", r"(?i)and\b"),
            ("OR", r"(?i)or\b"),
            ("NOT", r"(?i)not\b"),
            ("IN", r"(?i)in\b"),
            ("LIKE", r"(?i)like\b"),
            ("BETWEEN", r"(?i)between\b"),
            ("IS", r"(?i)is\b"),
            ("NULL", r"(?i)null\b"),
            ("AS", r"(?i)as\b"),
            ("JOIN", r"(?i)join\b"),
            ("INNER", r"(?i)inner\b"),
            ("OUTER", r"(?i)outer\b"),
            ("LEFT", r"(?i)left\b"),
            ("RIGHT", r"(?i)right\b"),
            ("ON", r"(?i)on\b"),
            ("GROUP", r"(?i)group\b"),
            ("BY", r"(?i)by\b"),
            ("HAVING", r"(?i)having\b"),
            ("ORDER", r"(?i)order\b"),
            ("ASC", r"(?i)asc\b"),
            ("DESC", r"(?i)desc\b"),
            ("LIMIT", r"(?i)limit\b"),
            ("OFFSET", r"(?i)offset\b"),
            ("SET", r"(?i)set\b"),
            ("VALUES", r"(?i)values\b"),
            ("INTO", r"(?i)into\b"),
            ("CREATE", r"(?i)create\b"),
            ("TABLE", r"(?i)table\b"),
            ("PRIMARY", r"(?i)primary\b"),
            ("KEY", r"(?i)key\b"),
            ("FOREIGN", r"(?i)foreign\b"),
            ("UNIQUE", r"(?i)unique\b"),
            ("NOT", r"(?i)not\b"),
            ("NULL", r"(?i)null\b"),
            ("AUTO_INCREMENT", r"(?i)auto_increment\b"),
            ("INT", r"(?i)int\b"),
            ("VARCHAR", r"(?i)varchar\b"),
            ("IDENTIFIER", r"[a-zA-Z_][a-zA-Z0-9_]*"),
            ("OPERATOR", r"[=<>!]+"),
            ("NUMBER", r"\d+(\.\d+)?"),
            ("STRING", r"'[^']*'"),
            ("COMMA", r","),
            ("SEMICOLON", r";"),
            ("DOT", r"\."),
            ("LEFT_PARENTHESIS", r"\("),
            ("RIGHT_PARENTHESIS", r"\)"),
            ("ASTERISK", r"\*"),
            ("PLUS", r"\+"),
            ("MINUS", r"-"),
            ("DIVIDE", r"/"),
            ("PERCENT", r"%")
        ]

        # Buscar y extraer tokens del SQL
        while sql:
            match = None
            for token_type, pattern in token_patterns:
                regex = re.compile(pattern)
                match = regex.match(sql)
                if match:
                    token = Lexico(token_type, match.group(0))
                    tokens.append(token)
                    sql = sql[len(token.value):].strip()
                    break
            if not match:
                raise TokenNoReconocidoError("Token no reconocido en la entrada")


        return tokens

class Sintaxis:
    def __init__(self):
        self.patterns = {
            "DELETE": re.compile(r"^\s*DELETE\s+FROM\s+(\w+)\s*(WHERE\s+(.+))?\s*;\s*$", re.IGNORECASE),
            "CREATE": re.compile(r"^\s*CREATE\s+TABLE\s+(\w+)\s*\((.+)\)\s*;\s*$", re.IGNORECASE),
            "INSERT": re.compile(r"^\s*INSERT\s+INTO\s+(\w+)\s*(\((.+)\))?\s+VALUES\s*\((.+)\)\s*;\s*$", re.IGNORECASE),
            "SELECT": re.compile(r"^\s*SELECT\s+([\w\*,\s]+)\s+FROM\s+(\w+)\s*(WHERE\s+(.+))?\s*;\s*$", re.IGNORECASE),
            "UPDATE": re.compile(r"^\s*UPDATE\s+(\w+)\s+SET\s+(.+)\s*(WHERE\s+(.+))?\s*;\s*$", re.IGNORECASE)
        }
        self.data_types = [
            "int",
            "varchar",    
            "float",    
            "double",    
            "boolean",    
            "number",    
            "string",    
            "integer",   
            "char",    
            "date",    
            "time",    
            "timestamp",    
            "binary",    
            "decimal",
            "blob"]
        self.reserved_words = [
            "SELECT", 
            "INSERT", 
            "UPDATE", 
            "DELETE", 
            "FROM", 
            "WHERE", 
            "AND", 
            "OR",
            "NOT", 
            "IN", 
            "LIKE", 
            "BETWEEN", 
            "IS", 
            "NULL", 
            "AS", 
            "JOIN", 
            "INNER",        
            "OUTER", 
            "LEFT", 
            "RIGHT", 
            "ON", 
            "GROUP", 
            "BY", 
            "HAVING", 
            "ORDER",        
            "ASC", 
            "DESC", 
            "LIMIT", 
            "OFFSET", 
            "SET", 
            "VALUES", 
            "INTO", 
            "CREATE",        
            "TABLE", 
            "PRIMARY", 
            "KEY", 
            "FOREIGN", 
            "UNIQUE", 
            "AUTO_INCREMENT",        
            "INT", 
            "VARCHAR", 
            "BOOLEAN", 
            "TINYINT", 
            "SMALLINT", 
            "MEDIUMINT",        
            "BIGINT", 
            "FLOAT", 
            "DOUBLE", 
            "DECIMAL", 
            "DATE", 
            "TIME", 
            "DATETIME",        
            "TIMESTAMP", 
            "YEAR", 
            "CHAR", 
            "BINARY", 
            "VARBINARY", 
            "TEXT", 
            "BLOB",        
            "ENUM", 
            "CASE", 
            "WHEN", 
            "THEN", 
            "ELSE", 
            "END"
            ]

    def parse(self, query):
        for action, pattern in self.patterns.items():
            match = pattern.match(query)
            if match:
                return self._parse_query(action, match)
        raise SyntaxError("Error de sintaxis: no se reconoce la sentencia SQL")  

    def _parse_query(self, action, match):
        if action == "DELETE":
            table = match.group(1)
            where_clause = match.group(3)
            return {"action": action, "table": table, "where": where_clause}

        elif action == "CREATE":
            table = match.group(1)
            if table.upper() in self.reserved_words:
                raise LexicalError(f"Palabra reservada '{table}' no puede ser usado como nombre de tabla.")
            self.check_table_exists(table)  # Agregar esta línea
            columns = []
            columns_string = match.group(2)
            for column in columns_string.split(","):
                column = column.strip()
                parts = column.split()
                if len(parts) != 2 or parts[1].lower() not in self.data_types:
                    raise TableError(f"Tipo de dato inválido en la columna: {column}")
                columns.append((parts[0], parts[1]))
            return {"action": action, "table": table, "columns": columns}

        elif action == "INSERT":
            table = match.group(1)
            columns = match.group(3) if match.group(3) else None
            values_string = match.group(4)
            values = self._parse_values(values_string)

            return {"action": action, "table": table, "columns": columns, "values": values}

        elif action == "SELECT":
            fields = match.group(1)
            table = match.group(2)
            where_clause = match.group(4)
            return {"action": action, "fields": fields, "table": table, "where": where_clause}

        elif action == "UPDATE":
            table = match.group(1)
            assignments = match.group(2)
            where_clause = match.group(4)
            self.check_data_exists(table, where_clause,assignments)  # Agregar esta línea
            return {"action": action, "table": table, "assignments": assignments, "where": where_clause}

        else:
            raise SyntaxError(f"Error sintáctico: la acción '{action}'.")

    # Verifica si la tabla existe al hacer un create
    def check_table_exists(self, table_name):
        if table_name in self.existing_tables:
            raise SemanticError(f"Error semántico: la tabla '{table_name}' ya existe")

    # Verifica si la tabla existe al usar insert
    def table_exists(self, table_name):
        connection = sqlite3.connect('prueba.db')
        c = connection.cursor()
        c.execute(f"SELECT count(*) FROM sqlite_master WHERE type='table' AND name='{table_name}'")
        exists = c.fetchone()[0] == 1
        connection.close()
        return exists

    def fetch_existing_tables(self):
        connection = sqlite3.connect('prueba.db')
        c = connection.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table'")
        self.existing_tables = {row[0] for row in c.fetchall()}
        connection.close()

    # Valida la cantidad de columnas coincida con la cantidad de datos a insertar
    def get_table_columns(self, table_name):
        connection = sqlite3.connect('prueba.db')
        c = connection.cursor()
        c.execute(f"PRAGMA table_info({table_name})")
        columns = [row[1] for row in c.fetchall()]
        connection.close()
        return columns

    # Valida el contenido de los valores a insertar
    def _parse_values(self, values_string):
        values = []
        in_string = False
        current_value = ''
        for char in values_string:
            if char == ',' and not in_string:
                values.append(current_value.strip())
                current_value = ''
            else:
                current_value += char
                if char == "'":
                    in_string = not in_string
        values.append(current_value.strip())
        return values

    # Verifica si el dato a buscar en la consulta de un update existe
    def check_data_exists(self, table, where_clause, assignments=None):
        if not self.table_exists(table):
            raise SemanticError(f"Error semántico: la tabla '{table}' no existe")

        columns = self.get_table_columns(table)

        # Verificar si las columnas de la cláusula WHERE y SET existen
        if where_clause is not None:
            # Validar si la cláusula WHERE está en un formato válido
            where_parts = where_clause.strip().split()
            if len(where_parts) != 3 or where_parts[1] != '=' or ',' in where_clause:
                raise SemanticError(f"Error semántico: la cláusula WHERE '{where_clause}' no tiene un formato válido")

            where_column = where_parts[0].strip()
            if where_column not in columns:
                raise SemanticError(f"Error semántico: la columna '{where_column}' no existe en la tabla '{table}'")
            
        if assignments is not None:
            assignment_columns = [part.strip().split('=')[0] for part in assignments.split(',')]
            for column in assignment_columns:
                if column not in columns:
                    raise SemanticError(f"Error semántico: la columna '{column}' no existe en la tabla '{table}'")

        # Consulta SELECT para verificar si existe algún dato que coincida con la cláusula WHERE
        if where_clause is not None:
            connection = sqlite3.connect('prueba.db')
            c = connection.cursor()

            try:
                query = f"SELECT COUNT(*) FROM {table} WHERE {where_clause}"
                c.execute(query)
                count = c.fetchone()[0]
            except sqlite3.Error:
                raise SemanticError(f"Error semántico: se produjo un error al procesar la cláusula WHERE: '{where_clause}'")

            connection.close()

            if count == 0:
                raise SemanticError(f"Error semántico: no se encontró ningún dato que coincida con la cláusula WHERE: '{where_clause}'")


# UPDATE staff set id=3 where ad=22;
# UPDATE staff set id=3 where ad=2,js=2;

class SQLAnalyzerApp(QWidget):
    def __init__(self):
        super().__init__()

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Analizador SQL")

        layout = QVBoxLayout()

        self.sql_input = QLineEdit()
        self.sql_input.setPlaceholderText("Ingresa la consulta SQL aquí")
        self.sql_input.textChanged.connect(self.adjust_input_size)
        layout.addWidget(self.sql_input)

        self.result_label = QLabel()
        layout.addWidget(self.result_label)

        self.analyze_button = QPushButton("Analizar")
        self.analyze_button.clicked.connect(self.analyze_sql)
        layout.addWidget(self.analyze_button)

        self.result_table = QTableWidget()
        layout.addWidget(self.result_table)
        
        self.setLayout(layout)

    def adjust_input_size(self):
        self.sql_input.setMinimumHeight(self.sql_input.sizeHint().height())

    def analyze_sql(self):
        query = self.sql_input.text()
        connection = sqlite3.connect('prueba.db')  # Cambia 'nombre_de_tu_base_de_datos.db' por el nombre de tu base de datos
        c = connection.cursor()

        try:
            tokens = FormatoLexico.lex(query)
            self.validate_table_column_names(tokens)

            for token in tokens:
                print(token)

            syntax = Sintaxis()
            syntax.fetch_existing_tables()
            # syntax.parse(query)
            parsed_query = syntax.parse(query)
            
            # Verificar si la tabla existe antes de hacer un INSERT
            if parsed_query['action'] == 'INSERT':
                table = parsed_query['table']
                if not syntax.table_exists(table):
                    raise SemanticError(f"Error semántico: la tabla '{table}' no existe")

                # Validar que la cantidad de columnas coincida con la cantidad de valores proporcionados
                columns = syntax.get_table_columns(table)
                values = parsed_query['values']
                if len(columns) != len(values):
                    raise SemanticError(f"Error semántico: la cantidad de columnas ({len(columns)}) no coincide con la cantidad de valores proporcionados ({len(values)})")
            
            if parsed_query['action'] == 'UPDATE':
                table = parsed_query['table']
                where_clause = parsed_query['where']
                assignments = parsed_query['assignments']

                syntax.check_data_exists(table, where_clause, assignments)

            c.execute(query)
            connection.commit()
            if "SELECT" in query.upper():
                self.populate_table(c.fetchall(), [desc[0] for desc in c.description])
                self.result_label.setText("Análisis exitoso")
                self.result_label.setStyleSheet("color: green")
            else:
                self.result_label.setText("Análisis exitoso")
                self.result_label.setStyleSheet("color: green")

        except (ValueError, LexicalError, SyntaxError, TableError, SemanticError) as e:
            self.result_label.setText(str(e))
            self.result_label.setStyleSheet("color: red")
        except TokenNoReconocidoError as e:
            error_message = (f"Error léxico: {e.args[0]} en la posición {e.error_position}.")
            self.result_label.setText(error_message)
            self.result_label.setStyleSheet("color: red")
        except Exception as e:
            self.result_label.setText(str(e))
            self.result_label.setStyleSheet("color: red")

        connection.close()

    def populate_table(self, result, headers):
        self.result_table.clear()

        self.result_table.setRowCount(len(result))
        self.result_table.setColumnCount(len(headers))

        for i, row in enumerate(result):
            for j, value in enumerate(row):
                self.result_table.setItem(i, j, QTableWidgetItem(str(value)))

        self.result_table.setHorizontalHeaderLabels(headers)

    def validate_table_column_names(self, tokens):
        # Verificar si es una consulta SELECT
        if tokens[0].token_type != "SELECT":
            return

        # Obtener la posición del token FROM en la consulta
        from_index = None
        for i, token in enumerate(tokens):
            if token.token_type == "FROM":
                from_index = i
                break

        # Obtener una lista de todos los identificadores y asteriscos en la consulta
        table_column_names = [(i, token.value) for i, token in enumerate(tokens) if token.token_type in ("IDENTIFIER", "ASTERISK")]

        # Verificar que cada tabla y columna existe en la base de datos
        connection = sqlite3.connect('prueba.db')
        c = connection.cursor()

        for i, table_column_name in table_column_names:
            # Ignorar el asterisco
            if table_column_name == "*":
                continue

            # Verificar si el identificador es un nombre de tabla o columna
            is_table_name = i > from_index

            if is_table_name:
                # Verificar que la tabla existe
                try:
                    c.execute(f"SELECT count(*) FROM sqlite_master WHERE type='table' AND name='{table_column_name}'")
                    if c.fetchone()[0] == 0:
                        raise SemanticError(f"Error semántico: no existe la tabla '{table_column_name}'")
                except SemanticError as e:
                    raise e
            else:
                table_column_parts = table_column_name.split(".")
                if len(table_column_parts) == 2:
                    table_name, column_name = table_column_parts

                    # Verificar que la columna existe en la tabla
                    c.execute(f"PRAGMA table_info({table_name})")
                    table_columns = [row[1] for row in c.fetchall()]
                    if column_name not in table_columns:
                        error_message = f"Error semántico: no existe la columna '{column_name}' en la tabla '{table_name}'"
                        raise SemanticError(error_message)
                elif len(table_column_parts) == 1:
                    # Verificar que la columna existe en alguna de las tablas utilizadas en la consulta
                    column_name = table_column_parts[0]
                    c.execute(f"SELECT name FROM sqlite_master WHERE type='table'")
                    table_names = [row[0] for row in c.fetchall()]

                    found_column = False
                    for table_name in table_names:
                        c.execute(f"PRAGMA table_info({table_name})")
                        table_columns = [row[1] for row in c.fetchall()]
                        if column_name in table_columns:
                            found_column = True
                            break

                    if not found_column:
                        error_message = f"Error semántico: no existe la columna '{column_name}' en ninguna tabla utilizada en la consulta"
                        raise SemanticError(error_message)
                else:
                    raise SemanticError(f"Error semántico: nombre de tabla y columna inválido '{table_column_name}'")
    
        connection.close()

    def check_table_exists(self, table_name):
        connection = sqlite3.connect('prueba.db')
        c = connection.cursor()
        try:
            c.execute(f"SELECT count(*) FROM sqlite_master WHERE type='table' AND name='{table_name}'")
            row = c.fetchone()
            if not row or row[0] == 0:
                raise SemanticError(f"Error semántico: no existe la tabla '{table_name}'")
        except SemanticError as e:
            raise e



# Insert into staff values (1,'w');
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SQLAnalyzerApp()
    window.show()
    sys.exit(app.exec_())
