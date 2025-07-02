# generate_docs.py
import os
import ast
import inspect

def extract_docstrings(file_path):
    """Extract docstrings from Python file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read())
        
        docs = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                docstring = ast.get_docstring(node)
                if docstring:
                    docs.append({
                        'name': node.name,
                        'type': 'class' if isinstance(node, ast.ClassDef) else 'function',
                        'docstring': docstring
                    })
        return docs
    except:
        return []

def generate_module_docs():
    """Generate documentation for core modules"""
    core_modules = [
        'app/core/validators.py',
        'app/core/cache_manager.py', 
        'app/core/advanced_theme_manager.py',
        'app/core/context_menu_manager.py'
    ]
    
    docs_content = "# Module Documentation\n\n"
    
    for module_path in core_modules:
        if os.path.exists(module_path):
            module_name = os.path.basename(module_path).replace('.py', '')
            docs_content += f"## {module_name}\n\n"
            
            docstrings = extract_docstrings(module_path)
            for doc in docstrings:
                docs_content += f"### {doc['name']} ({doc['type']})\n"
                docs_content += f"{doc['docstring']}\n\n"
    
    with open('docs/MODULES.md', 'w', encoding='utf-8') as f:
        f.write(docs_content)
    
    print("Module documentation generated: docs/MODULES.md")

if __name__ == '__main__':
    os.makedirs('docs', exist_ok=True)
    generate_module_docs()