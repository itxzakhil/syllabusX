import sqlite3
import os
import json
from werkzeug.security import generate_password_hash

DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database", "assessment.db")

def upgrade_and_seed():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 1. Update questions table columns if missing
    for col in ["unit", "topic", "concept", "skill", "difficulty"]:
        rows = cursor.execute("PRAGMA table_info(questions)").fetchall()
        if not any(r["name"] == col for r in rows):
            cursor.execute(f"ALTER TABLE questions ADD COLUMN {col} TEXT")
            print(f"Added column {col} to questions table.")

    # 2. Create faculty table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS faculty (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            department TEXT DEFAULT 'Computer Science & Engineering',
            designation TEXT DEFAULT 'Assistant Professor',
            password_hash TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    print("Faculty table ensured.")

    # 3. Seed demo faculty accounts
    demo_faculty = [
        ("Prof. Rajesh Sharma", "faculty@college.edu", "Computer Science & Engineering", "Associate Professor", "Faculty@123"),
        ("Dr. Anita Verma", "anita.singh@college.edu", "Information Technology", "HOD & Professor", "Faculty@123")
    ]
    for name, email, dept, desig, pwd in demo_faculty:
        exists = cursor.execute("SELECT id FROM faculty WHERE email = ?", (email,)).fetchone()
        if not exists:
            cursor.execute("""
                INSERT INTO faculty (name, email, department, designation, password_hash)
                VALUES (?, ?, ?, ?, ?)
            """, (name, email, dept, desig, generate_password_hash(pwd)))
            print(f"Created demo faculty: {email}")

    # 4. Ensure demo admin
    admin_exists = cursor.execute("SELECT id FROM admins WHERE email = 'admin@college.edu'").fetchone()
    if not admin_exists:
        cursor.execute("""
            INSERT INTO admins (name, email, password_hash)
            VALUES (?, ?, ?)
        """, ("College Admin", "admin@college.edu", generate_password_hash("Admin@123")))
        print("Created demo admin: admin@college.edu")

    # 5. Seed C Programming course
    c_instructions = """
C Programming Assessment Instructions

1. Make sure you have a stable internet connection.
2. The MCQ section contains 20 questions covering Units 1 to 5.
3. The MCQ section has a 20-minute time limit.
4. Questions are mapped to syllabus units, topics, and core competencies.
5. After submitting the MCQ section, you will proceed to the coding section.
6. The coding section contains 3 coding challenges.
7. The coding section has a total time limit of 60 minutes.
8. Read problem statements and input/output formats carefully before submitting.
9. Do not refresh, close, minimize, or switch away from the assessment.
10. Tab switching or leaving the page will terminate the attempt immediately.
11. Each student is allowed only one attempt per course.
""".strip()

    c_course = cursor.execute("SELECT id FROM courses WHERE code = 'C'").fetchone()
    if not c_course:
        cursor.execute("""
            INSERT INTO courses (name, code, description, instructions, mcq_duration_minutes, coding_duration_minutes, is_active)
            VALUES (?, ?, ?, ?, ?, ?, 1)
        """, (
            "C Programming",
            "C",
            "Procedural programming, pointers, memory allocation, arrays, strings, and structures in C.",
            c_instructions,
            20,
            60
        ))
        c_course_id = cursor.lastrowid
        print("Created C Programming course.")
    else:
        c_course_id = c_course["id"]

    # 6. Seed Java Programming course
    java_instructions = """
Java Programming Assessment Instructions

1. Make sure you have a stable internet connection.
2. The MCQ section contains 20 questions covering Java & OOP concepts.
3. The MCQ section has a 20-minute time limit.
4. Questions are mapped to syllabus units, topics, and core competencies.
5. After submitting the MCQ section, you will proceed to the coding section.
6. The coding section contains 3 coding challenges.
7. The coding section has a total time limit of 60 minutes.
8. Read problem statements and input/output formats carefully before submitting.
9. Do not refresh, close, minimize, or switch away from the assessment.
10. Tab switching or leaving the page will terminate the attempt immediately.
11. Each student is allowed only one attempt per course.
""".strip()

    java_course = cursor.execute("SELECT id FROM courses WHERE code = 'JAVA'").fetchone()
    if not java_course:
        cursor.execute("""
            INSERT INTO courses (name, code, description, instructions, mcq_duration_minutes, coding_duration_minutes, is_active)
            VALUES (?, ?, ?, ?, ?, ?, 1)
        """, (
            "Java Programming",
            "JAVA",
            "Object-Oriented Programming, classes, inheritance, polymorphism, exceptions, collections, and algorithms in Java.",
            java_instructions,
            20,
            60
        ))
        java_course_id = cursor.lastrowid
        print("Created Java Programming course.")
    else:
        java_course_id = java_course["id"]

    # 7. Seed 20 C MCQs if none exist
    c_mcq_count = cursor.execute("SELECT COUNT(*) AS cnt FROM questions WHERE course_id = ? AND question_type = 'mcq'", (c_course_id,)).fetchone()["cnt"]
    if c_mcq_count == 0:
        c_mcqs = [
            ("Which standard C header file must be included to use printf() and scanf()?",
             "<stdlib.h>", "<stdio.h>", "<string.h>", "<math.h>", "B",
             "Unit 1: Fundamentals", "Data Types & I/O", "Header Files", "Syntax & Logic", "Easy"),

            ("What is the result of the bitwise AND expression (6 & 3) in C?",
             "2", "3", "7", "0", "A",
             "Unit 1: Fundamentals", "Operators", "Bitwise Operations", "Syntax & Logic", "Medium"),

            ("Which storage class preserves a local variable's value between consecutive function calls?",
             "auto", "register", "static", "extern", "C",
             "Unit 1: Fundamentals", "Variables & Storage", "Static Storage", "Memory Management", "Medium"),

            ("Which loop in C is guaranteed to execute its loop body at least once?",
             "for loop", "while loop", "do-while loop", "nested loop", "C",
             "Unit 2: Control Flow", "Loops", "Do-While Semantics", "Algorithmic Thinking", "Easy"),

            ("In a C switch statement, what happens if a matching case does not end with a 'break' statement?",
             "Compilation error", "Execution falls through to subsequent cases", "Program terminates immediately", "Switch restarts", "B",
             "Unit 2: Control Flow", "Conditionals", "Switch Fall-through", "Syntax & Logic", "Medium"),

            ("What runtime condition occurs if a recursive function in C lacks a terminating base case?",
             "Stack Overflow (Segmentation fault)", "Out of Heap memory error", "Deadlock", "Syntax Error", "A",
             "Unit 3: Functions", "Recursion", "Stack Frames & Base Case", "Algorithmic Thinking", "Medium"),

            ("How can a C function modify a variable defined in the caller function's scope?",
             "By returning multiple values", "By passing the variable's address (pointer)", "By declaring it volatile", "By using typedef", "B",
             "Unit 3: Functions", "Parameters", "Call by Address", "Memory Management", "Medium"),

            ("Which operator is used to obtain the value stored at the memory address held by a pointer?",
             "&", "*", "->", "%", "B",
             "Unit 4: Pointers", "Pointer Basics", "Dereferencing Operator", "Pointer Arithmetic", "Easy"),

            ("If an int pointer 'ptr' stores address 2000, what is the value of 'ptr + 2' assuming sizeof(int) is 4 bytes?",
             "2002", "2004", "2008", "2016", "C",
             "Unit 4: Pointers", "Pointer Arithmetic", "Address Calculations", "Pointer Arithmetic", "Medium"),

            ("What value is typically assigned to a pointer to indicate it points to no valid memory address?",
             "-1", "0 or NULL", "VOID", "EOF", "B",
             "Unit 4: Pointers", "Pointer Safety", "NULL Pointer", "Memory Management", "Easy"),

            ("What is the valid index range for an array declared as 'int arr[10];'?",
             "1 to 10", "0 to 9", "0 to 10", "-1 to 9", "B",
             "Unit 4: Arrays & Strings", "Array Basics", "0-Based Indexing", "Syntax & Logic", "Easy"),

            ("Which character is used by standard C library functions to identify the end of a string?",
             "'\\n'", "'\\0'", "'EOF'", "' '", "B",
             "Unit 4: Arrays & Strings", "String Handling", "Null Terminator", "Syntax & Logic", "Easy"),

            ("Which standard library function allocates uninitialized contiguous memory on the heap?",
             "calloc()", "malloc()", "realloc()", "alloc()", "B",
             "Unit 5: Dynamic Memory", "Heap Allocation", "malloc() Function", "Memory Management", "Medium"),

            ("How does calloc() differ primarily from malloc() in C?",
             "calloc() allocates from stack", "calloc() initializes allocated memory bytes to zero", "calloc() cannot be freed", "calloc() is faster", "B",
             "Unit 5: Dynamic Memory", "Heap Allocation", "calloc() vs malloc()", "Memory Management", "Medium"),

            ("What critical issue arises when dynamically allocated memory is never released using free()?",
             "Buffer Overflow", "Memory Leak", "Dangling Pointer", "Segmentation Fault", "B",
             "Unit 5: Dynamic Memory", "Deallocation", "Memory Leaks", "Memory Management", "Easy"),

            ("Which operator is used to access structure members through a structure pointer?",
             ".", "->", "::", "*", "B",
             "Unit 5: Structures", "Structure Syntax", "Member Access via Pointer", "Data Structures", "Easy"),

            ("How is memory allocated for a union variable in C?",
             "Sum of all member sizes", "Size equal to its largest member", "Fixed 32 bytes", "Product of member sizes", "B",
             "Unit 5: Structures", "Unions", "Shared Memory Layout", "Memory Management", "Hard"),

            ("Which preprocessor directive is used to define symbolic constants and inline macros?",
             "#include", "#define", "#pragma", "#typedef", "B",
             "Unit 1: Fundamentals", "Preprocessor", "Macro Substitution", "Syntax & Logic", "Easy"),

            ("Which mode string in fopen() opens an existing file for reading and writing without file truncation?",
             "\"w+\"", "\"r+\"", "\"a\"", "\"rw\"", "B",
             "Unit 1: Fundamentals", "File Handling", "File Open Modes", "Syntax & Logic", "Medium"),

            ("What is the scope of a variable declared inside a block surrounded by curly braces {} in C?",
             "File scope", "Block/local scope", "Program scope", "Extern scope", "B",
             "Unit 3: Functions", "Scope Rules", "Block Scope", "Syntax & Logic", "Easy")
        ]

        for idx, mcq in enumerate(c_mcqs, start=1):
            cursor.execute("""
                INSERT INTO questions (
                    course_id, question_type, question_text,
                    option_a, option_b, option_c, option_d, correct_option,
                    points, order_number, is_active,
                    unit, topic, concept, skill, difficulty
                )
                VALUES (?, 'mcq', ?, ?, ?, ?, ?, ?, 1, ?, 1, ?, ?, ?, ?, ?)
            """, (c_course_id, mcq[0], mcq[1], mcq[2], mcq[3], mcq[4], mcq[5], idx, mcq[6], mcq[7], mcq[8], mcq[9], mcq[10]))
        print("Inserted 20 C MCQs.")

    # 8. Seed 3 C Coding Questions if none exist
    c_coding_count = cursor.execute("SELECT COUNT(*) AS cnt FROM questions WHERE course_id = ? AND question_type = 'coding'", (c_course_id,)).fetchone()["cnt"]
    if c_coding_count == 0:
        c_coding_questions = [
            ("Sum of Digits in C",
             """Write a complete C program that reads an integer from standard input and prints the sum of its digits.

Input format: a single integer (e.g. 123, 4059, 999).""",
             [
                 {"input": "123", "output": "6"},
                 {"input": "4059", "output": "18"},
                 {"input": "999", "output": "27"}
             ],
             "Unit 2: Control Flow & Loops", "Loops & Modulo Arithmetic", "Digit Extraction", "Algorithmic Thinking"),

            ("Reverse a String in C",
             """Write a complete C program that reads a single word string from standard input and prints its reverse.

Input format: a single word string without spaces (e.g. hello, syllabus, college).""",
             [
                 {"input": "hello", "output": "olleh"},
                 {"input": "syllabus", "output": "suballys"},
                 {"input": "college", "output": "egelloc"}
             ],
             "Unit 4: Arrays & Strings", "String Manipulation", "Character Inversion", "Memory & Pointer Manipulation"),

            ("Check Prime Number in C",
             """Write a complete C program that reads a positive integer n (n >= 2) and prints PRIME if it is a prime number, otherwise prints NOT_PRIME.

Input format: a single integer n >= 2 (e.g. 7, 12, 23).""",
             [
                 {"input": "7", "output": "PRIME"},
                 {"input": "12", "output": "NOT_PRIME"},
                 {"input": "23", "output": "PRIME"}
             ],
             "Unit 3: Functions & Control Flow", "Algorithmic Efficiency", "Primality Testing", "Problem Solving")
        ]

        for idx, cq in enumerate(c_coding_questions, start=1):
            cursor.execute("""
                INSERT INTO questions (
                    course_id, question_type, question_text,
                    coding_input_description, coding_expected_output,
                    points, order_number, is_active,
                    unit, topic, concept, skill, difficulty
                )
                VALUES (?, 'coding', ?, ?, ?, 10, ?, 1, ?, ?, ?, ?, 'Medium')
            """, (c_course_id, cq[0], cq[1], json.dumps(cq[2]), idx, cq[3], cq[4], cq[5], cq[6]))
        print("Inserted 3 C Coding Questions.")

    # 9. Seed 20 Java MCQs if none exist
    java_mcq_count = cursor.execute("SELECT COUNT(*) AS cnt FROM questions WHERE course_id = ? AND question_type = 'mcq'", (java_course_id,)).fetchone()["cnt"]
    if java_mcq_count == 0:
        java_mcqs = [
            ("What allows Java programs to achieve the 'Write Once, Run Anywhere' (WORA) capability?",
             "Native machine compilation", "Java Virtual Machine (JVM) executing bytecode", "Operating system drivers", "Just-In-Time Assembler", "B",
             "Unit 1: Java Basics", "JVM Architecture", "Bytecode Execution", "System Understanding", "Easy"),

            ("What is the default initial value of an uninitialized boolean instance variable in a Java class?",
             "true", "false", "null", "0", "B",
             "Unit 1: Java Basics", "Data Types", "Default Values", "Syntax & Logic", "Easy"),

            ("Which access modifier restricts the visibility of a class member strictly to within its own class?",
             "public", "protected", "private", "package-private", "C",
             "Unit 2: OOP Concepts", "Encapsulation", "Access Modifiers", "Object-Oriented Design", "Easy"),

            ("Which keyword is used in Java to establish class inheritance?",
             "implements", "extends", "inherits", "super", "B",
             "Unit 2: OOP Concepts", "Inheritance", "Class Extension", "Object-Oriented Design", "Easy"),

            ("Which statement must appear as the very first line of a subclass constructor to invoke the superclass constructor?",
             "this();", "super();", "parent();", "base();", "B",
             "Unit 2: OOP Concepts", "Constructors", "Super Constructor Calling", "Object-Oriented Design", "Medium"),

            ("In method overriding in Java, at what point is the method call bound to the implementation?",
             "Compile time", "Run time (dynamic dispatch)", "Class loading time", "Bytecode verification time", "B",
             "Unit 3: Polymorphism", "Method Overriding", "Dynamic Dispatch", "Object-Oriented Design", "Medium"),

            ("What distinguishes overloaded methods in the same Java class?",
             "Return type only", "Parameter count or parameter types", "Access modifier only", "Thrown exceptions only", "B",
             "Unit 3: Polymorphism", "Method Overloading", "Compile-Time Polymorphism", "Syntax & Logic", "Medium"),

            ("Which keyword is used by a Java class to implement an interface?",
             "extends", "implements", "interface", "abstract", "B",
             "Unit 3: Interfaces", "Interface Realization", "Multiple Inheritance of Type", "Object-Oriented Design", "Easy"),

            ("Since Java 8, which keyword allows writing a non-abstract method with an implementation body inside an interface?",
             "static", "default", "concrete", "final", "B",
             "Unit 3: Interfaces", "Default Methods", "Interface Evolution", "Object-Oriented Design", "Medium"),

            ("What happens when you modify a String object using methods like concat() in Java?",
             "The existing String is modified in place", "A new String object is created in memory", "An exception is thrown", "The JVM crashes", "B",
             "Unit 4: Strings", "String Immutability", "String Constant Pool", "Memory Management", "Medium"),

            ("Which class is the preferred high-performance choice for mutable string operations in a single-threaded environment?",
             "String", "StringBuilder", "StringBuffer", "CharSequence", "B",
             "Unit 4: Strings", "Mutable Sequences", "StringBuilder Performance", "Performance Optimization", "Medium"),

            ("Which block in a Java try-catch structure always executes whether an exception occurs or not?",
             "try", "catch", "finally", "throws", "C",
             "Unit 4: Exception Handling", "Try-Catch-Finally", "Finally Block Execution", "Exception Handling", "Easy"),

            ("Which of the following is an unchecked (Runtime) exception in Java?",
             "IOException", "SQLException", "NullPointerException", "ClassNotFoundException", "C",
             "Unit 4: Exception Handling", "Exception Hierarchy", "Unchecked Exceptions", "Exception Handling", "Medium"),

            ("Which keyword is placed in a method signature to declare that it may throw one or more checked exceptions?",
             "throw", "throws", "catching", "exception", "B",
             "Unit 4: Exception Handling", "Exception Propagation", "Throws Clause", "Exception Handling", "Easy"),

            ("Which Java Collection offers O(1) constant time performance for accessing elements by index?",
             "LinkedList", "ArrayList", "HashSet", "PriorityQueue", "B",
             "Unit 5: Collections", "List Implementations", "ArrayList Indexing", "Data Structures", "Medium"),

            ("Which interface in Java Collections does NOT permit duplicate elements?",
             "List", "Set", "Queue", "Vector", "B",
             "Unit 5: Collections", "Set Interface", "Uniqueness Guarantees", "Data Structures", "Easy"),

            ("Which collection class stores data in key-value pairs and allows one null key in Java?",
             "TreeMap", "HashMap", "Hashtable", "LinkedHashSet", "B",
             "Unit 5: Collections", "Map Interface", "HashMap Hashing", "Data Structures", "Easy"),

            ("How are unreachable objects on the Java heap reclaimed in Java?",
             "Explicit free() call", "Automatic Garbage Collector", "delete operator", "Destructors", "B",
             "Unit 1: Java Basics", "Memory Management", "Garbage Collection", "Memory Management", "Easy"),

            ("What does the 'static' keyword indicate when applied to a class member in Java?",
             "The member belongs to the class rather than instances", "The member cannot be changed", "The member is private", "The member is transient", "A",
             "Unit 2: OOP Concepts", "Static Members", "Class-Level Scope", "Object-Oriented Design", "Easy"),

            ("What is the effect of declaring a class as 'final' in Java?",
             "It cannot be instantiated", "It cannot be subclassed/inherited", "All its methods become static", "All its fields become public", "B",
             "Unit 2: OOP Concepts", "Modifiers", "Final Classes", "Syntax & Logic", "Medium")
        ]

        for idx, mcq in enumerate(java_mcqs, start=1):
            cursor.execute("""
                INSERT INTO questions (
                    course_id, question_type, question_text,
                    option_a, option_b, option_c, option_d, correct_option,
                    points, order_number, is_active,
                    unit, topic, concept, skill, difficulty
                )
                VALUES (?, 'mcq', ?, ?, ?, ?, ?, ?, 1, ?, 1, ?, ?, ?, ?, ?)
            """, (java_course_id, mcq[0], mcq[1], mcq[2], mcq[3], mcq[4], mcq[5], idx, mcq[6], mcq[7], mcq[8], mcq[9], mcq[10]))
        print("Inserted 20 Java MCQs.")

    # 10. Seed 3 Java Coding Questions if none exist
    java_coding_count = cursor.execute("SELECT COUNT(*) AS cnt FROM questions WHERE course_id = ? AND question_type = 'coding'", (java_course_id,)).fetchone()["cnt"]
    if java_coding_count == 0:
        java_coding_questions = [
            ("Factorial of a Number in Java",
             """Write a complete Java program that reads an integer n (0 <= n <= 10) from standard input and prints its factorial.

Input format: a single integer n (e.g. 5, 0, 6).""",
             [
                 {"input": "5", "output": "120"},
                 {"input": "0", "output": "1"},
                 {"input": "6", "output": "720"}
             ],
             "Unit 2: OOP & Methods", "Methods & Loops", "Factorial Calculation", "Algorithmic Thinking"),

            ("Palindrome Check in Java",
             """Write a complete Java program that reads a string from standard input and prints YES if it is a palindrome, otherwise prints NO.

Input format: a single word string (e.g. radar, java, level).""",
             [
                 {"input": "radar", "output": "YES"},
                 {"input": "java", "output": "NO"},
                 {"input": "level", "output": "YES"}
             ],
             "Unit 4: Strings & Exceptions", "String Processing", "Palindrome Verification", "String Manipulation"),

            ("Count Vowels in Java",
             """Write a complete Java program that reads a single word from standard input and prints the total number of vowels (a, e, i, o, u) in it.

Input format: a single word without spaces (e.g. college, syllabus, education).""",
             [
                 {"input": "college", "output": "3"},
                 {"input": "syllabus", "output": "2"},
                 {"input": "education", "output": "5"}
             ],
             "Unit 4: Strings", "Character Analysis", "Vowel Counting", "String Processing")
        ]

        for idx, cq in enumerate(java_coding_questions, start=1):
            cursor.execute("""
                INSERT INTO questions (
                    course_id, question_type, question_text,
                    coding_input_description, coding_expected_output,
                    points, order_number, is_active,
                    unit, topic, concept, skill, difficulty
                )
                VALUES (?, 'coding', ?, ?, ?, 10, ?, 1, ?, ?, ?, ?, 'Medium')
            """, (java_course_id, cq[0], cq[1], json.dumps(cq[2]), idx, cq[3], cq[4], cq[5], cq[6]))
        print("Inserted 3 Java Coding Questions.")

    # 11. Update Python MCQs with unit, topic, concept, skill if null
    py_course = cursor.execute("SELECT id FROM courses WHERE code = 'PYTHON'").fetchone()
    if py_course:
        cursor.execute("""
            UPDATE questions
            SET unit = 'Unit 1: Python Basics',
                topic = 'Syntax & Functions',
                concept = 'Function Definitions',
                skill = 'Syntax & Logic',
                difficulty = 'Easy'
            WHERE course_id = ? AND question_type = 'mcq' AND unit IS NULL
        """, (py_course["id"],))

        cursor.execute("""
            UPDATE questions
            SET unit = 'Unit 2: Data Structures & Algorithms',
                topic = 'Problem Solving',
                concept = 'Implementation',
                skill = 'Algorithmic Thinking',
                difficulty = 'Medium'
            WHERE course_id = ? AND question_type = 'coding' AND unit IS NULL
        """, (py_course["id"],))

    conn.commit()
    conn.close()
    print("Database upgrade & seed completed successfully!")

if __name__ == "__main__":
    upgrade_and_seed()
