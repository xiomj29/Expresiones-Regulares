import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import xml.etree.ElementTree as ET
import json
import os
import re
from graphviz import Digraph

# Clase que representa un estado en un autómata
class State:
    def __init__(self, name, is_initial=False, is_final=False):
        self.name = name
        self.is_initial = is_initial
        self.is_final = is_final

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name

# Clase que implementa un Autómata Finito Determinista (AFD)
class AFD:
    def __init__(self):
        self.states = []
        self.alphabet = set()
        self.initial_state = None
        self.final_states = []
        self.transitions = {}

    def add_state(self, state, is_initial=False, is_final=False):
        new_state = State(state, is_initial, is_final)
        self.states.append(new_state)
        if is_initial:
            self.initial_state = new_state
        if is_final:
            self.final_states.append(new_state)
        return new_state

    def add_transition(self, from_state, symbol, to_state):
        if symbol not in self.alphabet and symbol != '':
            self.alphabet.add(symbol)
        self.transitions[(from_state, symbol)] = to_state

    def get_state_by_name(self, name):
        for state in self.states:
            if state.name == name:
                return state
        return None

    def validate_string(self, input_string):
        if not self.initial_state:
            return False, []

        current_state = self.initial_state
        steps = [(current_state, 0, input_string)]

        for i, symbol in enumerate(input_string):
            if (current_state, symbol) not in self.transitions:
                return False, steps + [(None, i+1, input_string[i+1:])]

            current_state = self.transitions[(current_state, symbol)]
            steps.append((current_state, i+1, input_string[i+1:]))

        return current_state in self.final_states, steps

    def to_afd_format(self):
        data = {
            "alphabet": list(self.alphabet),
            "states": [state.name for state in self.states],
            "initial_state": self.initial_state.name if self.initial_state else "",
            "final_states": [state.name for state in self.final_states],
            "transitions": {
                f"{from_state.name},{symbol}": to_state.name 
                for (from_state, symbol), to_state in self.transitions.items()
            }
        }
        return data

    @classmethod
    def from_afd_format(cls, data):
        afd = cls()
        for state_name in data["states"]:
            is_initial = state_name == data["initial_state"]
            is_final = state_name in data["final_states"]
            afd.add_state(state_name, is_initial, is_final)

        for transition_key, to_state_name in data["transitions"].items():
            from_state_name, symbol = transition_key.split(",")
            from_state = afd.get_state_by_name(from_state_name)
            to_state = afd.get_state_by_name(to_state_name)
            if from_state and to_state:
                afd.add_transition(from_state, symbol, to_state)

        return afd

    @classmethod
    def from_jff_format(cls, jff_content):
        afd = cls()
        root = ET.fromstring(jff_content)
        state_elements = root.findall(".//state")
        id_to_name = {}
        id_to_state = {}

        for state_elem in state_elements:
            state_id = state_elem.get("id")
            state_name = state_elem.get("name", state_id)
            id_to_name[state_id] = state_name
            is_initial = state_elem.find("initial") is not None
            is_final = state_elem.find("final") is not None
            state = afd.add_state(state_name, is_initial, is_final)
            id_to_state[state_id] = state

        transition_elements = root.findall(".//transition")
        for trans_elem in transition_elements:
            from_id = trans_elem.find("from").text
            to_id = trans_elem.find("to").text
            read_elem = trans_elem.find("read")
            symbol = read_elem.text if read_elem is not None and read_elem.text else ""
            from_state = id_to_state[from_id]
            to_state = id_to_state[to_id]
            afd.add_transition(from_state, symbol, to_state)

        return afd

    def to_regex(self):
        """Convierte el AFD a una expresión regular usando el método de eliminación de estados"""
        states = self.states.copy()
        transitions = {}
        
        # Crear matriz de transiciones inicial
        for (from_state, symbol), to_state in self.transitions.items():
            if from_state not in transitions:
                transitions[from_state] = {}
            transitions[from_state][to_state] = symbol

        # Agregar estados inicial y final si no existen
        initial = self.initial_state
        finals = self.final_states
        
        # Si hay múltiples estados finales, agregar un nuevo estado final único
        if len(finals) > 1:
            new_final = State("qf", is_final=True)
            states.append(new_final)
            for final_state in finals:
                if final_state not in transitions:
                    transitions[final_state] = {}
                transitions[final_state][new_final] = ""
            finals = [new_final]
        
        final = finals[0] if finals else None
        
        # Eliminar estados uno por uno (excepto inicial y final)
        states_to_remove = [s for s in states if s != initial and s != final]
        
        for state in states_to_remove:
            # Encontrar todos los estados que llegan a este estado
            incoming = {}
            for from_state in transitions:
                if state in transitions[from_state]:
                    incoming[from_state] = transitions[from_state][state]
            
            # Encontrar todas las transiciones salientes de este estado
            outgoing = {}
            if state in transitions:
                for to_state in transitions[state]:
                    if to_state != state:  # Ignorar bucles por ahora
                        outgoing[to_state] = transitions[state][to_state]
            
            # Encontrar el bucle en el estado (si existe)
            loop = ""
            if state in transitions and state in transitions[state]:
                loop = transitions[state][state]
                if loop:
                    loop = f"({loop})*"
                else:
                    loop = ""
            
            # Para cada par de estados entrante/saliente, agregar nueva transición
            for from_state in incoming:
                for to_state in outgoing:
                    # Construir la expresión para la nueva transición
                    in_expr = incoming[from_state]
                    out_expr = outgoing[to_state]
                    
                    new_expr_parts = []
                    if in_expr:
                        new_expr_parts.append(in_expr)
                    if loop:
                        new_expr_parts.append(loop)
                    if out_expr:
                        new_expr_parts.append(out_expr)
                    
                    new_expr = "".join(new_expr_parts)
                    
                    # Agregar la nueva transición
                    if from_state not in transitions:
                        transitions[from_state] = {}
                    if to_state in transitions[from_state]:
                        # Si ya existe una transición, combinarla con OR
                        existing = transitions[from_state][to_state]
                        if existing:
                            new_expr = f"({existing})+({new_expr})" if new_expr else existing
                        else:
                            new_expr = existing + new_expr
                    transitions[from_state][to_state] = new_expr
            
            # Eliminar el estado de la matriz de transiciones
            if state in transitions:
                del transitions[state]
            for from_state in transitions:
                if state in transitions[from_state]:
                    del transitions[from_state][state]
        
        # Obtener la expresión regular entre el estado inicial y final
        if initial in transitions and final in transitions[initial]:
            regex = transitions[initial][final]
        else:
            regex = ""
        
        # Simplificar la expresión regular
        regex = self.simplify_regex(regex)
        
        return regex

    def simplify_regex(self, regex):
        """Simplifica la expresión regular eliminando paréntesis innecesarios y otros simplificaciones"""
        if not regex:
            return regex
        
        # Simplificar (a)* a a*
        while "(.)*" in regex:
            regex = regex.replace("(.)*", ".*")
        
        # Simplificar (a+b) a a|b
        while "+" in regex:
            regex = regex.replace("+", "|")
        
        # Eliminar paréntesis redundantes
        while "(.)" in regex:
            regex = regex.replace("(.)", ".")
        
        return regex

    def visualize(self, filename="afd"):
        """Genera una visualización del AFD usando Graphviz"""
        dot = Digraph()
        dot.attr(rankdir='LR')
        
        # Agregar estados
        for state in self.states:
            if state.is_initial:
                dot.node(state.name, shape="circle", style="bold")
                # Agregar nodo invisible para la flecha inicial
                dot.node("start", shape="point", style="invis")
                dot.edge("start", state.name)
            elif state.is_final:
                dot.node(state.name, shape="doublecircle")
            else:
                dot.node(state.name, shape="circle")
        
        # Agregar transiciones
        transition_map = {}
        for (from_state, symbol), to_state in self.transitions.items():
            key = (from_state.name, to_state.name)
            if key not in transition_map:
                transition_map[key] = []
            transition_map[key].append(symbol)
        
        for (from_name, to_name), symbols in transition_map.items():
            label = ",".join(symbols) if symbols else "ε"
            dot.edge(from_name, to_name, label=label)
        
        # Guardar y mostrar el gráfico
        dot.render(filename, format='png', cleanup=True)
        return filename + ".png"

# Clase que implementa un Autómata Finito No Determinista (NFA)
class NFA:
    def __init__(self):
        self.states = []
        self.alphabet = set()
        self.initial_state = None
        self.final_states = []
        self.transitions = {}

    def add_state(self, state, is_initial=False, is_final=False):
        new_state = State(state, is_initial, is_final)
        self.states.append(new_state)
        if is_initial:
            self.initial_state = new_state
        if is_final:
            self.final_states.append(new_state)
        return new_state

    def add_transition(self, from_state, symbol, to_state):
        if symbol not in self.alphabet and symbol != '':
            self.alphabet.add(symbol)
        key = (from_state, symbol)
        if key not in self.transitions:
            self.transitions[key] = []
        self.transitions[key].append(to_state)

    def lambda_closure(self, states):
        closure = set(states)
        stack = list(states)

        while stack:
            state = stack.pop()
            key = (state, '')
            if key in self.transitions:
                for next_state in self.transitions[key]:
                    if next_state not in closure:
                        closure.add(next_state)
                        stack.append(next_state)

        return closure

    def validate_string(self, input_string):
        current_states = self.lambda_closure({self.initial_state})
        steps = [(current_states, 0, input_string)]

        for i, symbol in enumerate(input_string):
            next_states = set()
            for state in current_states:
                key = (state, symbol)
                if key in self.transitions:
                    next_states.update(self.transitions[key])
            current_states = self.lambda_closure(next_states)
            steps.append((current_states, i+1, input_string[i+1:]))

        return any(state in self.final_states for state in current_states), steps

    def to_dfa(self):
        dfa = AFD()
        initial_closure = self.lambda_closure({self.initial_state})
        dfa_state_map = {frozenset(initial_closure): dfa.add_state('q0', is_initial=True)}
        stack = [initial_closure]

        while stack:
            current_states = stack.pop()
            current_dfa_state = dfa_state_map[frozenset(current_states)]

            for symbol in self.alphabet:
                next_states = set()
                for state in current_states:
                    key = (state, symbol)
                    if key in self.transitions:
                        next_states.update(self.transitions[key])
                next_closure = self.lambda_closure(next_states)

                if not next_closure:
                    continue

                if frozenset(next_closure) not in dfa_state_map:
                    new_state_name = f'q{len(dfa_state_map)}'
                    is_final = any(state in self.final_states for state in next_closure)
                    dfa_state_map[frozenset(next_closure)] = dfa.add_state(new_state_name, is_final=is_final)
                    stack.append(next_closure)

                dfa.add_transition(current_dfa_state, symbol, dfa_state_map[frozenset(next_closure)])

        return dfa

    @classmethod
    def from_jff_format(cls, jff_content):
        nfa = cls()
        root = ET.fromstring(jff_content)
        state_elements = root.findall(".//state")
        id_to_name = {}
        id_to_state = {}

        for state_elem in state_elements:
            state_id = state_elem.get("id")
            state_name = state_elem.get("name", state_id)
            id_to_name[state_id] = state_name
            is_initial = state_elem.find("initial") is not None
            is_final = state_elem.find("final") is not None
            state = nfa.add_state(state_name, is_initial, is_final)
            id_to_state[state_id] = state

        transition_elements = root.findall(".//transition")
        for trans_elem in transition_elements:
            from_id = trans_elem.find("from").text
            to_id = trans_elem.find("to").text
            read_elem = trans_elem.find("read")
            symbol = read_elem.text if read_elem is not None and read_elem.text else ""
            from_state = id_to_state[from_id]
            to_state = id_to_state[to_id]
            nfa.add_transition(from_state, symbol, to_state)

        return nfa

# Clase para manejar expresiones regulares y sus validaciones
class RegexValidator:
    @staticmethod
    def validate_email(email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.fullmatch(pattern, email)), pattern
    
    @staticmethod
    def validate_phone(phone):
        # Patrón para números de teléfono en formato internacional o nacional
        pattern = r'^(\+\d{1,3}\s?)?(\d{2,3}[\s-]?)?\d{3,4}[\s-]?\d{3,4}$'
        return bool(re.fullmatch(pattern, phone)), pattern
    
    @staticmethod
    def validate_url(url):
        pattern = r'^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$'
        return bool(re.fullmatch(pattern, url)), pattern
    
    @staticmethod
    def validate_date(date):
        # Patrón para fechas en formato DD/MM/YYYY o YYYY-MM-DD
        pattern = r'^(\d{2}\/\d{2}\/\d{4})|(\d{4}-\d{2}-\d{2})$'
        return bool(re.fullmatch(pattern, date)), pattern
    
    @staticmethod
    def validate_password(password):
        # Al menos 8 caracteres, una mayúscula, una minúscula, un número y un carácter especial
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        return bool(re.fullmatch(pattern, password)), pattern

# Clase principal de la aplicación con interfaz gráfica
class AFDSimulator(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Simulador de Autómatas Finitos y Expresiones Regulares")
        self.geometry("1200x800")
        self.current_afd = AFD()
        self.current_nfa = None
        self.simulation_steps = []
        self.current_step = 0
        self.regex_conversion_steps = []
        self.current_regex_step = 0
        self.setup_ui()

    def setup_ui(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Pestañas principales
        self.definition_tab = ttk.Frame(self.notebook)
        self.simulation_tab = ttk.Frame(self.notebook)
        self.regex_tab = ttk.Frame(self.notebook)
        self.tools_tab = ttk.Frame(self.notebook)
        self.regex_validator_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.definition_tab, text="Definición de AFD")
        self.notebook.add(self.simulation_tab, text="Simulación")
        self.notebook.add(self.regex_tab, text="Conversión a ER")
        self.notebook.add(self.tools_tab, text="Herramientas")
        self.notebook.add(self.regex_validator_tab, text="Validadores ER")
        
        self.setup_definition_tab()
        self.setup_simulation_tab()
        self.setup_regex_tab()
        self.setup_tools_tab()
        self.setup_regex_validator_tab()

    def setup_definition_tab(self):
        state_frame = ttk.LabelFrame(self.definition_tab, text="Definición de Estados")
        state_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(state_frame, text="Nombre del estado:").grid(row=0, column=0, padx=5, pady=5)
        self.state_name_var = tk.StringVar()
        ttk.Entry(state_frame, textvariable=self.state_name_var, width=20).grid(row=0, column=1, padx=5, pady=5)
        
        self.is_initial_var = tk.BooleanVar()
        ttk.Checkbutton(state_frame, text="Estado inicial", variable=self.is_initial_var).grid(row=0, column=2, padx=5, pady=5)
        
        self.is_final_var = tk.BooleanVar()
        ttk.Checkbutton(state_frame, text="Estado de aceptación", variable=self.is_final_var).grid(row=0, column=3, padx=5, pady=5)
        
        ttk.Button(state_frame, text="Agregar Estado", command=self.add_state).grid(row=0, column=4, padx=5, pady=5)

        transition_frame = ttk.LabelFrame(self.definition_tab, text="Definición de Transiciones")
        transition_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(transition_frame, text="Estado origen:").grid(row=0, column=0, padx=5, pady=5)
        self.from_state_var = tk.StringVar()
        self.from_state_combobox = ttk.Combobox(transition_frame, textvariable=self.from_state_var, state="readonly", width=15)
        self.from_state_combobox.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(transition_frame, text="Símbolo:").grid(row=0, column=2, padx=5, pady=5)
        self.symbol_var = tk.StringVar()
        ttk.Entry(transition_frame, textvariable=self.symbol_var, width=5).grid(row=0, column=3, padx=5, pady=5)
        
        ttk.Label(transition_frame, text="Estado destino:").grid(row=0, column=4, padx=5, pady=5)
        self.to_state_var = tk.StringVar()
        self.to_state_combobox = ttk.Combobox(transition_frame, textvariable=self.to_state_var, state="readonly", width=15)
        self.to_state_combobox.grid(row=0, column=5, padx=5, pady=5)
        
        ttk.Button(transition_frame, text="Agregar Transición", command=self.add_transition).grid(row=0, column=6, padx=5, pady=5)

        table_frame = ttk.LabelFrame(self.definition_tab, text="Tabla de Transiciones")
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.transitions_tree = ttk.Treeview(table_frame)
        self.transitions_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        x_scrollbar = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.transitions_tree.xview)
        x_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        y_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.transitions_tree.yview)
        y_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.transitions_tree.configure(xscrollcommand=x_scrollbar.set, yscrollcommand=y_scrollbar.set)

        buttons_frame = ttk.Frame(self.definition_tab)
        buttons_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(buttons_frame, text="Cargar Autómata", command=self.load_afd).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(buttons_frame, text="Guardar Autómata", command=self.save_afd).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(buttons_frame, text="Reiniciar Autómata", command=self.reset_afd).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(buttons_frame, text="Convertir NFA a DFA", command=self.convert_nfa_to_dfa).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(buttons_frame, text="Visualizar AFD", command=self.visualize_afd).pack(side=tk.LEFT, padx=5, pady=5)

    def setup_simulation_tab(self):
        input_frame = ttk.Frame(self.simulation_tab)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text="Cadena a validar:").pack(side=tk.LEFT, padx=5, pady=5)
        
        self.input_string_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.input_string_var, width=30).pack(side=tk.LEFT, padx=5, pady=5)
        
        ttk.Button(input_frame, text="Validar", command=self.validate_string).pack(side=tk.LEFT, padx=5, pady=5)

        result_frame = ttk.Frame(self.simulation_tab)
        result_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.validation_result_var = tk.StringVar()
        self.validation_result_label = ttk.Label(result_frame, textvariable=self.validation_result_var, font=("Arial", 12))
        self.validation_result_label.pack(padx=5, pady=5)

        sim_frame = ttk.LabelFrame(self.simulation_tab, text="Simulación paso a paso")
        sim_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.current_position_var = tk.StringVar()
        ttk.Label(sim_frame, textvariable=self.current_position_var, font=("Arial", 10)).pack(padx=5, pady=5, anchor=tk.W)
        
        self.simulation_text = scrolledtext.ScrolledText(sim_frame, width=80, height=15)
        self.simulation_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        control_frame = ttk.Frame(sim_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(control_frame, text="Paso anterior", command=self.prev_step).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(control_frame, text="Siguiente paso", command=self.next_step).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(control_frame, text="Reiniciar simulación", command=self.reset_simulation).pack(side=tk.LEFT, padx=5, pady=5)

    def setup_regex_tab(self):
        # Frame para la conversión a expresión regular
        conversion_frame = ttk.LabelFrame(self.regex_tab, text="Conversión de AFD a Expresión Regular")
        conversion_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Botón para iniciar la conversión
        ttk.Button(conversion_frame, text="Convertir AFD a ER", command=self.convert_afd_to_regex).pack(pady=5)
        
        # Área para mostrar los pasos de la conversión
        self.regex_steps_text = scrolledtext.ScrolledText(conversion_frame, width=80, height=15)
        self.regex_steps_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Frame para controles de navegación de pasos
        regex_control_frame = ttk.Frame(conversion_frame)
        regex_control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(regex_control_frame, text="Paso anterior", command=self.prev_regex_step).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(regex_control_frame, text="Siguiente paso", command=self.next_regex_step).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Área para mostrar el resultado final
        self.regex_result_var = tk.StringVar()
        ttk.Label(conversion_frame, textvariable=self.regex_result_var, font=("Arial", 12, "bold")).pack(pady=5)

    def setup_tools_tab(self):
        substrings_frame = ttk.LabelFrame(self.tools_tab, text="Subcadenas, Prefijos y Sufijos")
        substrings_frame.pack(fill=tk.X, padx=10, pady=5)
        
        input_frame = ttk.Frame(substrings_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Cadena para analizar:").pack(side=tk.LEFT, padx=5, pady=5)
        
        self.substring_input_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.substring_input_var, width=30).pack(side=tk.LEFT, padx=5, pady=5)
        
        ttk.Button(input_frame, text="Calcular", command=self.calculate_substrings).pack(side=tk.LEFT, padx=5, pady=5)

        results_frame = ttk.Frame(substrings_frame)
        results_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.substrings_text = scrolledtext.ScrolledText(results_frame, width=80, height=10)
        self.substrings_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        kleene_frame = ttk.LabelFrame(self.tools_tab, text="Cerradura de Kleene y Positiva")
        kleene_frame.pack(fill=tk.X, padx=10, pady=5)
        
        kleene_input_frame = ttk.Frame(kleene_frame)
        kleene_input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(kleene_input_frame, text="Alfabeto (ej: ab):").pack(side=tk.LEFT, padx=5, pady=5)
        
        self.kleene_alphabet_var = tk.StringVar()
        ttk.Entry(kleene_input_frame, textvariable=self.kleene_alphabet_var, width=15).pack(side=tk.LEFT, padx=5, pady=5)
        
        ttk.Label(kleene_input_frame, text="Longitud máxima:").pack(side=tk.LEFT, padx=5, pady=5)
        
        self.kleene_length_var = tk.StringVar(value="3")
        ttk.Entry(kleene_input_frame, textvariable=self.kleene_length_var, width=5).pack(side=tk.LEFT, padx=5, pady=5)
        
        ttk.Button(kleene_input_frame, text="Calcular", command=self.calculate_kleene).pack(side=tk.LEFT, padx=5, pady=5)

        kleene_results_frame = ttk.Frame(kleene_frame)
        kleene_results_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.kleene_text = scrolledtext.ScrolledText(kleene_results_frame, width=80, height=10)
        self.kleene_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def setup_regex_validator_tab(self):
        # Frame para selección de tipo de validación
        validator_frame = ttk.LabelFrame(self.regex_validator_tab, text="Validación con Expresiones Regulares")
        validator_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Selector de tipo de validación
        self.validator_type_var = tk.StringVar()
        validator_types = [
            "Correo electrónico",
            "Número telefónico",
            "URL",
            "Fecha",
            "Contraseña"
        ]
        
        ttk.Label(validator_frame, text="Tipo de validación:").pack(pady=5)
        validator_combobox = ttk.Combobox(validator_frame, textvariable=self.validator_type_var, 
                                        values=validator_types, state="readonly")
        validator_combobox.pack(pady=5)
        validator_combobox.bind("<<ComboboxSelected>>", self.update_validator_ui)
        
        # Frame para entrada de texto a validar
        input_frame = ttk.Frame(validator_frame)
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(input_frame, text="Texto a validar:").pack(side=tk.LEFT, padx=5)
        self.validator_input_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.validator_input_var, width=40).pack(side=tk.LEFT, padx=5)
        ttk.Button(input_frame, text="Validar", command=self.validate_with_regex).pack(side=tk.LEFT, padx=5)
        
        # Área para mostrar la expresión regular utilizada
        self.regex_pattern_var = tk.StringVar()
        ttk.Label(validator_frame, textvariable=self.regex_pattern_var, wraplength=600).pack(pady=5)
        
        # Área para mostrar el resultado de la validación
        self.validation_regex_result_var = tk.StringVar()
        validation_result_label = ttk.Label(validator_frame, textvariable=self.validation_regex_result_var, 
                                          font=("Arial", 12))
        validation_result_label.pack(pady=10)
        
        # Botón para ver el AFD equivalente
        ttk.Button(validator_frame, text="Ver AFD Equivalente", command=self.show_equivalent_afd).pack(pady=5)

    def add_state(self):
        state_name = self.state_name_var.get().strip()
        is_initial = self.is_initial_var.get()
        is_final = self.is_final_var.get()
        
        if not state_name:
            messagebox.showerror("Error", "El nombre del estado no puede estar vacío")
            return
        
        if self.current_afd.get_state_by_name(state_name):
            messagebox.showerror("Error", f"El estado {state_name} ya existe")
            return
        
        self.current_afd.add_state(state_name, is_initial, is_final)
        self.state_name_var.set("")
        self.is_initial_var.set(False)
        self.is_final_var.set(False)
        self.update_state_dropdowns()
        self.update_transitions_table()

    def add_transition(self):
        from_state_name = self.from_state_var.get()
        symbol = self.symbol_var.get().strip()
        to_state_name = self.to_state_var.get()
        
        if not from_state_name or not to_state_name:
            messagebox.showerror("Error", "Debe seleccionar los estados origen y destino")
            return
        
        if not symbol and symbol != '':
            messagebox.showerror("Error", "Debe ingresar un símbolo")
            return
        
        from_state = self.current_afd.get_state_by_name(from_state_name)
        to_state = self.current_afd.get_state_by_name(to_state_name)
        
        if (from_state, symbol) in self.current_afd.transitions:
            messagebox.showerror("Error", f"Ya existe una transición desde {from_state_name} con el símbolo {symbol}")
            return
        
        self.current_afd.add_transition(from_state, symbol, to_state)
        self.symbol_var.set("...")
        self.update_transitions_table()

    def validate_string(self):
        input_string = self.input_string_var.get()
        if input_string is None:
            return
        
        if self.current_nfa:
            is_accepted, steps = self.current_nfa.validate_string(input_string)
        else:
            is_accepted, steps = self.current_afd.validate_string(input_string)
        
        self.simulation_steps = steps
        self.current_step = 0
        
        if is_accepted:
            self.validation_result_var.set(f"La cadena '{input_string}' es ACEPTADA por el autómata")
            self.validation_result_label.configure(foreground="green")
        else:
            self.validation_result_var.set(f"La cadena '{input_string}' es RECHAZADA por el autómata")
            self.validation_result_label.configure(foreground="red")
        
        self.update_simulation_view()

    def next_step(self):
        if self.simulation_steps and self.current_step < len(self.simulation_steps) - 1:
            self.current_step += 1
            self.update_simulation_view()

    def prev_step(self):
        if self.simulation_steps and self.current_step > 0:
            self.current_step -= 1
            self.update_simulation_view()

    def reset_simulation(self):
        self.update_simulation_view()

    def load_afd(self):
        file_types = [("AFD Files", "*.afd"), ("JFLAP Files", "*.jff"), ("All Files", "*.*")]
        file_path = filedialog.askopenfilename(filetypes=file_types)
        
        if not file_path:
            return
        
        try:
            if file_path.endswith('.afd'):
                with open(file_path, 'r') as f:
                    afd_data = json.load(f)
                self.current_afd = AFD.from_afd_format(afd_data)
            elif file_path.endswith('.jff'):
                with open(file_path, 'r') as f:
                    jff_content = f.read()
                self.current_nfa = NFA.from_jff_format(jff_content)
                self.current_afd = self.current_nfa.to_dfa()
            
            self.update_state_dropdowns()
            self.update_transitions_table()
            messagebox.showinfo("Éxito", f"Autómata cargado desde {file_path}")
        except Exception as ex:
            messagebox.showerror("Error", f"Error al cargar el archivo: {str(ex)}")

    def save_afd(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".afd", 
                                               filetypes=[("AFD Files", "*.afd"), ("All Files", "*.*")])
        if not file_path:
            return
        
        try:
            afd_data = self.current_afd.to_afd_format()
            with open(file_path, 'w') as f:
                json.dump(afd_data, f, indent=2)
            messagebox.showinfo("Éxito", f"AFD guardado en {file_path}")
        except Exception as ex:
            messagebox.showerror("Error", f"Error al guardar: {str(ex)}")

    def reset_afd(self):
        self.current_afd = AFD()
        self.current_nfa = None
        self.simulation_steps = []
        self.current_step = 0
        self.update_state_dropdowns()
        self.update_transitions_table()
        self.validation_result_var.set("")
        self.simulation_text.delete(1.0, tk.END)
        self.current_position_var.set("")

    def calculate_substrings(self):
        input_string = self.substring_input_var.get()
        if not input_string:
            return
        
        substrings = []
        for i in range(len(input_string)):
            for j in range(i + 1, len(input_string) + 1):
                substrings.append(input_string[i:j])
        
        prefixes = [input_string[:i] for i in range(len(input_string) + 1)]
        suffixes = [input_string[i:] for i in range(len(input_string) + 1)]
        
        self.substrings_text.delete(1.0, tk.END)
        self.substrings_text.insert(tk.END, f"Subcadenas ({len(substrings)}):\n")
        self.substrings_text.insert(tk.END, ", ".join(substrings) + "\n\n")
        self.substrings_text.insert(tk.END, f"Prefijos ({len(prefixes)}):\n")
        self.substrings_text.insert(tk.END, ", ".join(prefixes) + "\n\n")
        self.substrings_text.insert(tk.END, f"Sufijos ({len(suffixes)}):\n")
        self.substrings_text.insert(tk.END, ", ".join(suffixes))

    def calculate_kleene(self):
        alphabet_input = self.kleene_alphabet_var.get()
        max_length_str = self.kleene_length_var.get()
        
        try:
            max_length = int(max_length_str)
        except ValueError:
            messagebox.showerror("Error", "La longitud máxima debe ser un número entero")
            return
        
        alphabet = []
        for char in alphabet_input:
            if char not in alphabet and not char.isspace():
                alphabet.append(char)
        
        if not alphabet:
            messagebox.showerror("Error", "El alfabeto no puede estar vacío")
            return
        
        kleene_star = [""]
        for length in range(1, max_length + 1):
            self.generate_strings(alphabet, "", length, kleene_star)
        
        kleene_plus = [s for s in kleene_star if s]
        
        self.kleene_text.delete(1.0, tk.END)
        self.kleene_text.insert(tk.END, f"Cerradura de Kleene (Σ*) - {len(kleene_star)} cadenas:\n")
        self.kleene_text.insert(tk.END, ", ".join(kleene_star) + "\n\n")
        self.kleene_text.insert(tk.END, f"Cerradura positiva (Σ+) - {len(kleene_plus)} cadenas:\n")
        self.kleene_text.insert(tk.END, ", ".join(kleene_plus))

    def update_state_dropdowns(self):
        state_names = [state.name for state in self.current_afd.states]
        self.from_state_combobox['values'] = state_names
        self.to_state_combobox['values'] = state_names

    def update_transitions_table(self):
        for item in self.transitions_tree.get_children():
            self.transitions_tree.delete(item)
        
        self.transitions_tree['columns'] = ['state'] + sorted(list(self.current_afd.alphabet))
        self.transitions_tree.column('#0', width=0, stretch=tk.NO)
        self.transitions_tree.column('state', anchor=tk.W, width=150)
        self.transitions_tree.heading('#0', text='', anchor=tk.CENTER)
        self.transitions_tree.heading('state', text='Estado', anchor=tk.CENTER)
        
        for symbol in sorted(self.current_afd.alphabet):
            self.transitions_tree.column(symbol, anchor=tk.CENTER, width=80)
            self.transitions_tree.heading(symbol, text=symbol, anchor=tk.CENTER)
        
        for state in self.current_afd.states:
            state_label = f"{state.name}{' (I)' if state.is_initial else ''}{' (F)' if state in self.current_afd.final_states else ''}"
            row_values = {'state': state_label}
            
            for symbol in sorted(self.current_afd.alphabet):
                next_state = self.current_afd.transitions.get((state, symbol), None)
                row_values[symbol] = next_state.name if next_state else "-"
            
            self.transitions_tree.insert('', tk.END, values=[row_values.get(col, '') for col in ['state'] + sorted(list(self.current_afd.alphabet))])

    def update_simulation_view(self):
        self.simulation_text.delete(1.0, tk.END)
        if not self.simulation_steps:
            return
        
        for i, (state, pos, remaining) in enumerate(self.simulation_steps):
            if i > self.current_step:
                break
            
            if i == self.current_step:
                state_text = f"→ Estado: {state.name if state else 'Error'}"
            else:
                state_text = f"Estado: {state.name if state else 'Error'}"
            
            self.simulation_text.insert(tk.END, f"Paso {i}: {state_text}\n")
        
        if self.simulation_steps and self.current_step < len(self.simulation_steps):
            current_state, pos, remaining = self.simulation_steps[self.current_step]
            input_string = self.input_string_var.get()
            
            if input_string:
                highlighted_string = ""
                for i, char in enumerate(input_string):
                    if i < pos:
                        highlighted_string += char
                    elif i == pos and self.current_step < len(self.simulation_steps) - 1:
                        highlighted_string += f"[{char}]"
                    else:
                        highlighted_string += char
                
                self.current_position_var.set(f"Posición actual: {highlighted_string}")

    def generate_strings(self, alphabet, current, length, result):
        if length == 0:
            result.append(current)
            return
        
        for symbol in alphabet:
            self.generate_strings(alphabet, current + symbol, length - 1, result)

    def convert_nfa_to_dfa(self):
        if self.current_nfa:
            self.current_afd = self.current_nfa.to_dfa()
            self.update_state_dropdowns()
            self.update_transitions_table()
            messagebox.showinfo("Éxito", "NFA convertido a DFA exitosamente")
        else:
            messagebox.showerror("Error", "No hay un NFA cargado para convertir")
            
    def visualize_afd(self):
        """Visualiza el AFD actual usando Graphviz"""
        if not self.current_afd.states:
            messagebox.showerror("Error", "No hay un AFD definido para visualizar")
            return
        
        try:
            filename = "current_afd"
            self.current_afd.visualize(filename)
            self.show_image_window(filename + '.png')
        except Exception as e:
            messagebox.showerror("Error", 
                            f"No se pudo generar la visualización.\n"
                            f"Asegúrate que Graphviz está instalado correctamente.\n"
                            f"Error técnico: {str(e)}")        
 
    def create_equivalent_afd(self, validator_type):
        """Crea un AFD equivalente para el tipo de validador seleccionado"""
        afd = AFD()
        
        if validator_type == "Correo electrónico":
            # Estados para validación de email
            q0 = afd.add_state("q0", is_initial=True)  # Inicio
            q1 = afd.add_state("q1")                   # Parte local
            q2 = afd.add_state("q2")                   # Después de @
            q3 = afd.add_state("q3", is_final=True)    # Dominio válido
            
            # Caracteres permitidos
            local_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+-"
            domain_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-"
            tld_chars = "abcdefghijklmnopqrstuvwxyz"
            
            # Transiciones
            for c in local_chars:
                afd.add_transition(q0, c, q1)
                afd.add_transition(q1, c, q1)
            
            afd.add_transition(q1, "@", q2)
            
            for c in domain_chars:
                afd.add_transition(q2, c, q2)
                afd.add_transition(q2, c, q3)
            
            afd.add_transition(q2, ".", q3)
            
            for c in tld_chars:
                afd.add_transition(q3, c, q3)

        elif validator_type == "Número telefónico":
            # Estados para teléfonos
            q0 = afd.add_state("q0", is_initial=True)
            q1 = afd.add_state("q1")  # Código de país opcional
            q2 = afd.add_state("q2")  # Código de área opcional
            q3 = afd.add_state("q3")  # Primera parte del número
            q4 = afd.add_state("q4", is_final=True)  # Número completo
            
            # Transiciones
            afd.add_transition(q0, "+", q1)
            
            for d in "0123456789":
                afd.add_transition(q0, d, q3)
                afd.add_transition(q1, d, q2)
                afd.add_transition(q2, d, q3)
                afd.add_transition(q3, d, q4)
                afd.add_transition(q4, d, q4)
            
            # Separadores opcionales
            afd.add_transition(q1, " ", q1)
            afd.add_transition(q2, " ", q2)
            afd.add_transition(q2, "-", q2)
            afd.add_transition(q3, " ", q3)
            afd.add_transition(q3, "-", q3)

        elif validator_type == "URL":
            # Estados para URLs
            q0 = afd.add_state("q0", is_initial=True)
            q1 = afd.add_state("q1")  # Después de http:// o https://
            q2 = afd.add_state("q2")  # Dominio principal
            q3 = afd.add_state("q3", is_final=True)  # URL completa
            
            # Transiciones
            afd.add_transition(q0, "h", q0)
            afd.add_transition(q0, "t", q0)
            afd.add_transition(q0, "p", q0)
            afd.add_transition(q0, "s", q0)
            afd.add_transition(q0, ":", q0)
            afd.add_transition(q0, "/", q1)
            afd.add_transition(q1, "/", q1)
            
            # Caracteres del dominio
            domain_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-"
            for c in domain_chars:
                afd.add_transition(q1, c, q2)
                afd.add_transition(q2, c, q2)
            
            afd.add_transition(q2, ".", q3)
            
            # Caracteres de ruta
            path_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/-_."
            for c in path_chars:
                afd.add_transition(q3, c, q3)

        elif validator_type == "Fecha":
            # Estados para fechas (DD/MM/AAAA o AAAA-MM-DD)
            q0 = afd.add_state("q0", is_initial=True)
            q1 = afd.add_state("q1")  # Primer dígito día/mes
            q2 = afd.add_state("q2")  # Segundo dígito día/mes
            q3 = afd.add_state("q3")  # Separador /
            q4 = afd.add_state("q4")  # Primer dígito mes/año
            q5 = afd.add_state("q5")  # Segundo dígito mes/año
            q6 = afd.add_state("q6")  # Separador /
            q7 = afd.add_state("q7")  # Año dígito 1
            q8 = afd.add_state("q8")  # Año dígito 2
            q9 = afd.add_state("q9")  # Año dígito 3
            q10 = afd.add_state("q10", is_final=True)  # Año dígito 4
            
            # Formato AAAA-MM-DD
            q11 = afd.add_state("q11")  # Primer -
            q12 = afd.add_state("q12")  # Primer dígito mes
            q13 = afd.add_state("q13")  # Segundo dígito mes
            q14 = afd.add_state("q14")  # Segundo -
            q15 = afd.add_state("q15")  # Primer dígito día
            q16 = afd.add_state("q16", is_final=True)  # Segundo dígito día
            
            # Transiciones para DD/MM/AAAA
            for d in "0123":
                afd.add_transition(q0, d, q1)
            afd.add_transition(q0, "0", q1)
            afd.add_transition(q0, "1", q1)
            afd.add_transition(q0, "2", q1)
            afd.add_transition(q0, "3", q1)
            
            for d in "0123456789":
                afd.add_transition(q1, d, q2)
            
            afd.add_transition(q2, "/", q3)
            
            for d in "01":
                afd.add_transition(q3, d, q4)
            
            for d in "0123456789":
                afd.add_transition(q4, d, q5)
            
            afd.add_transition(q5, "/", q6)
            
            for d in "12":
                afd.add_transition(q6, d, q7)
            
            for d in "0123456789":
                afd.add_transition(q7, d, q8)
                afd.add_transition(q8, d, q9)
                afd.add_transition(q9, d, q10)
            
            # Transiciones para AAAA-MM-DD
            for d in "12":
                afd.add_transition(q0, d, q7)
            
            for d in "0123456789":
                afd.add_transition(q7, d, q8)
                afd.add_transition(q8, d, q9)
                afd.add_transition(q9, d, q10)
            
            afd.add_transition(q10, "-", q11)
            
            for d in "01":
                afd.add_transition(q11, d, q12)
            
            for d in "0123456789":
                afd.add_transition(q12, d, q13)
            
            afd.add_transition(q13, "-", q14)
            
            for d in "0123":
                afd.add_transition(q14, d, q15)
            
            for d in "0123456789":
                afd.add_transition(q15, d, q16)

        elif validator_type == "Contraseña":
            # Estados para contraseñas complejas
            q0 = afd.add_state("q0", is_initial=True)  # Inicio
            q1 = afd.add_state("q1")  # Tiene minúscula
            q2 = afd.add_state("q2")  # Tiene mayúscula
            q3 = afd.add_state("q3")  # Tiene número
            q4 = afd.add_state("q4")  # Tiene especial
            q5 = afd.add_state("q5", is_final=True)  # Cumple todos
            
            # Caracteres
            lower = "abcdefghijklmnopqrstuvwxyz"
            upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            digits = "0123456789"
            special = "@$!%*?&"
            
            # Transiciones
            for c in lower:
                afd.add_transition(q0, c, q1)
                afd.add_transition(q1, c, q1)
                afd.add_transition(q2, c, q2)
                afd.add_transition(q3, c, q3)
                afd.add_transition(q4, c, q4)
                afd.add_transition(q5, c, q5)
            
            for c in upper:
                afd.add_transition(q0, c, q2)
                afd.add_transition(q1, c, q5)
                afd.add_transition(q2, c, q2)
                afd.add_transition(q3, c, q5)
                afd.add_transition(q4, c, q5)
                afd.add_transition(q5, c, q5)
            
            for c in digits:
                afd.add_transition(q0, c, q3)
                afd.add_transition(q1, c, q5)
                afd.add_transition(q2, c, q5)
                afd.add_transition(q3, c, q3)
                afd.add_transition(q4, c, q5)
                afd.add_transition(q5, c, q5)
            
            for c in special:
                afd.add_transition(q0, c, q4)
                afd.add_transition(q1, c, q5)
                afd.add_transition(q2, c, q5)
                afd.add_transition(q3, c, q5)
                afd.add_transition(q4, c, q4)
                afd.add_transition(q5, c, q5)
            
            # Transiciones para alcanzar longitud mínima
            for c in lower + upper + digits + special:
                afd.add_transition(q5, c, q5)
        
        return afd

    def visualize(self, filename="afd"):
        """Genera una visualización del AFD con mejor formato y tamaño"""
        try:
            import graphviz
        except ImportError:
            raise ImportError("Graphviz no está instalado. Ejecuta: pip install graphviz")

        # Configuración del gráfico
        dot = graphviz.Digraph(format='png')
        dot.attr(rankdir='LR', size="20,15", dpi="150", ratio="auto")
        dot.attr('node', shape='circle', fontsize='12', fontname='Arial')
        
        # Estados especiales
        for state in self.states:
            if state.is_initial and state.is_final:
                dot.node(state.name, shape='doublecircle', style='bold', width='1.2', height='1.2')
            elif state.is_initial:
                dot.node(state.name, style='bold', width='1.2', height='1.2')
            elif state.is_final:
                dot.node(state.name, shape='doublecircle', width='1.2', height='1.2')
            
            # Flecha para estado inicial
            if state.is_initial:
                dot.node(f"start_{state.name}", shape='point', width='0.1', height='0.1')
                dot.edge(f"start_{state.name}", state.name, arrowsize='0.8')

        # Transiciones
        transitions_grouped = {}
        for (from_state, symbol), to_state in self.transitions.items():
            key = (from_state.name, to_state.name)
            if key not in transitions_grouped:
                transitions_grouped[key] = []
            transitions_grouped[key].append(symbol)

        for (from_name, to_name), symbols in transitions_grouped.items():
            label = ", ".join(symbols) if symbols else "ε"
            dot.edge(from_name, to_name, label=label, fontsize='10', arrowsize='0.8')

        # Generar el archivo
        dot.render(filename, cleanup=True, view=False)
        return filename + '.png'

    def convert_afd_to_regex(self):
        """Convierte el AFD actual a una expresión regular"""
        if not self.current_afd.states:
            messagebox.showerror("Error", "No hay un AFD definido para convertir")
            return
        
        # Generar los pasos de la conversión
        self.regex_conversion_steps = []
        
        # Paso 1: Mostrar el AFD original
        self.regex_conversion_steps.append("=== AFD Original ===")
        self.regex_conversion_steps.append(f"Estados: {[s.name for s in self.current_afd.states]}")
        self.regex_conversion_steps.append(f"Estado inicial: {self.current_afd.initial_state.name if self.current_afd.initial_state else 'Ninguno'}")
        self.regex_conversion_steps.append(f"Estados finales: {[s.name for s in self.current_afd.final_states]}")
        self.regex_conversion_steps.append("Transiciones:")
        
        for (from_state, symbol), to_state in self.current_afd.transitions.items():
            self.regex_conversion_steps.append(f"  {from_state.name} --{symbol}--> {to_state.name}")
        
        # Paso 2: Aplicar el algoritmo de eliminación de estados
        states = self.current_afd.states.copy()
        transitions = {}
        
        # Crear matriz de transiciones inicial
        for (from_state, symbol), to_state in self.current_afd.transitions.items():
            if from_state not in transitions:
                transitions[from_state] = {}
            transitions[from_state][to_state] = symbol
        
        # Agregar estados inicial y final si no existen
        initial = self.current_afd.initial_state
        finals = self.current_afd.final_states
        
        # Si hay múltiples estados finales, agregar un nuevo estado final único
        if len(finals) > 1:
            new_final = State("qf", is_final=True)
            states.append(new_final)
            for final_state in finals:
                if final_state not in transitions:
                    transitions[final_state] = {}
                transitions[final_state][new_final] = ""
            finals = [new_final]
        
        final = finals[0] if finals else None
        
        # Eliminar estados uno por uno (excepto inicial y final)
        states_to_remove = [s for s in states if s != initial and s != final]
        
        for state in states_to_remove:
            self.regex_conversion_steps.append(f"\n=== Eliminando estado {state.name} ===")
            
            # Encontrar todos los estados que llegan a este estado
            incoming = {}
            for from_state in transitions:
                if state in transitions[from_state]:
                    incoming[from_state] = transitions[from_state][state]
            
            self.regex_conversion_steps.append(f"  Estados entrantes: {[f'{s.name} ({incoming[s]})' for s in incoming]}")
            
            # Encontrar todas las transiciones salientes de este estado
            outgoing = {}
            if state in transitions:
                for to_state in transitions[state]:
                    if to_state != state:  # Ignorar bucles por ahora
                        outgoing[to_state] = transitions[state][to_state]
            
            self.regex_conversion_steps.append(f"  Estados salientes: {[f'{s.name} ({outgoing[s]})' for s in outgoing]}")
            
            # Encontrar el bucle en el estado (si existe)
            loop = ""
            if state in transitions and state in transitions[state]:
                loop = transitions[state][state]
                if loop:
                    loop = f"({loop})*"
                else:
                    loop = ""
            
            self.regex_conversion_steps.append(f"  Bucle en el estado: {loop if loop else 'Ninguno'}")
            
            # Para cada par de estados entrante/saliente, agregar nueva transición
            for from_state in incoming:
                for to_state in outgoing:
                    # Construir la expresión para la nueva transición
                    in_expr = incoming[from_state]
                    out_expr = outgoing[to_state]
                    
                    new_expr_parts = []
                    if in_expr:
                        new_expr_parts.append(in_expr)
                    if loop:
                        new_expr_parts.append(loop)
                    if out_expr:
                        new_expr_parts.append(out_expr)
                    
                    new_expr = "".join(new_expr_parts)
                    
                    # Agregar la nueva transición
                    if from_state not in transitions:
                        transitions[from_state] = {}
                    if to_state in transitions[from_state]:
                        # Si ya existe una transición, combinarla con OR
                        existing = transitions[from_state][to_state]
                        if existing:
                            new_expr = f"({existing})+({new_expr})" if new_expr else existing
                        else:
                            new_expr = existing + new_expr
                    
                    transitions[from_state][to_state] = new_expr
                    
                    self.regex_conversion_steps.append(
                        f"  Nueva transición: {from_state.name} --{new_expr}--> {to_state.name}")
            
            # Eliminar el estado de la matriz de transiciones
            if state in transitions:
                del transitions[state]
            for from_state in transitions:
                if state in transitions[from_state]:
                    del transitions[from_state][state]
        
        # Obtener la expresión regular entre el estado inicial y final
        if initial in transitions and final in transitions[initial]:
            regex = transitions[initial][final]
        else:
            regex = ""
        
        # Simplificar la expresión regular
        regex = self.simplify_regex(regex)
        
        self.regex_conversion_steps.append("\n=== Expresión Regular Final ===")
        self.regex_conversion_steps.append(regex)
        
        # Mostrar el primer paso
        self.current_regex_step = 0
        self.update_regex_conversion_view()
        
        # Mostrar el resultado final
        self.regex_result_var.set(f"Expresión Regular Resultante: {regex}")

    def simplify_regex(self, regex):
        """Simplifica la expresión regular eliminando paréntesis innecesarios y otros simplificaciones"""
        if not regex:
            return regex
        
        # Simplificar (a)* a a*
        while "(.)*" in regex:
            regex = regex.replace("(.)*", ".*")
        
        # Simplificar (a+b) a a|b
        while "+" in regex:
            regex = regex.replace("+", "|")
        
        # Eliminar paréntesis redundantes
        while "(.)" in regex:
            regex = regex.replace("(.)", ".")
        
        return regex

    def update_regex_conversion_view(self):
        """Actualiza la vista de conversión a expresión regular con el paso actual"""
        self.regex_steps_text.delete(1.0, tk.END)
        
        if not self.regex_conversion_steps:
            return
        
        # Mostrar todos los pasos hasta el actual
        for i in range(min(self.current_regex_step + 1, len(self.regex_conversion_steps))):
            self.regex_steps_text.insert(tk.END, self.regex_conversion_steps[i] + "\n\n")

    def next_regex_step(self):
        """Avanza al siguiente paso en la conversión a ER"""
        if self.regex_conversion_steps and self.current_regex_step < len(self.regex_conversion_steps) - 1:
            self.current_regex_step += 1
            self.update_regex_conversion_view()

    def prev_regex_step(self):
        """Retrocede al paso anterior en la conversión a ER"""
        if self.regex_conversion_steps and self.current_regex_step > 0:
            self.current_regex_step -= 1
            self.update_regex_conversion_view()



    def update_validator_ui(self, event=None):
        """Actualiza la UI del validador según el tipo seleccionado"""
        validator_type = self.validator_type_var.get()
        
        if validator_type == "Correo electrónico":
            self.regex_pattern_var.set(r"Patrón: ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
        elif validator_type == "Número telefónico":
            self.regex_pattern_var.set(r"Patrón: ^(\+\d{1,3}\s?)?(\d{2,3}[\s-]?)?\d{3,4}[\s-]?\d{3,4}$")
        elif validator_type == "URL":
            self.regex_pattern_var.set(r"Patrón: ^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$")
        elif validator_type == "Fecha":
            self.regex_pattern_var.set(r"Patrón: ^(\d{2}\/\d{2}\/\d{4})|(\d{4}-\d{2}-\d{2})$")
        elif validator_type == "Contraseña":
            self.regex_pattern_var.set(r"Patrón: ^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$")

    def validate_with_regex(self):
        """Valida el texto de entrada según el patrón de expresión regular seleccionado"""
        validator_type = self.validator_type_var.get()
        input_text = self.validator_input_var.get()
        
        if not validator_type:
            messagebox.showerror("Error", "Seleccione un tipo de validación")
            return
        
        if not input_text:
            messagebox.showerror("Error", "Ingrese un texto para validar")
            return
        
        # Obtener todos los widgets Label en el frame de validación
        labels = [child for child in self.regex_validator_tab.winfo_children() 
                if isinstance(child, ttk.Label)]
        
        # Buscar el label de resultado (asumimos que es el último Label)
        result_label = None
        for label in labels:
            if label['textvariable'] == self.validation_regex_result_var:
                result_label = label
                break
        
        if validator_type == "Correo electrónico":
            is_valid, pattern = RegexValidator.validate_email(input_text)
            message = "es VÁLIDO" if is_valid else "NO es válido"
            self.validation_regex_result_var.set(f"El correo electrónico '{input_text}' {message}")
        elif validator_type == "Número telefónico":
            is_valid, pattern = RegexValidator.validate_phone(input_text)
            message = "es VÁLIDO" if is_valid else "NO es válido"
            self.validation_regex_result_var.set(f"El número telefónico '{input_text}' {message}")
        elif validator_type == "URL":
            is_valid, pattern = RegexValidator.validate_url(input_text)
            message = "es VÁLIDA" if is_valid else "NO es válida"
            self.validation_regex_result_var.set(f"La URL '{input_text}' {message}")
        elif validator_type == "Fecha":
            is_valid, pattern = RegexValidator.validate_date(input_text)
            message = "es VÁLIDA" if is_valid else "NO es válida"
            self.validation_regex_result_var.set(f"La fecha '{input_text}' {message}")
        elif validator_type == "Contraseña":
            is_valid, pattern = RegexValidator.validate_password(input_text)
            message = "es VÁLIDA" if is_valid else "NO cumple con los requisitos"
            self.validation_regex_result_var.set(f"La contraseña {message}")
        
        # Cambiar color según el resultado
        if result_label:
            if is_valid:
                self.validation_regex_result_var.set(self.validation_regex_result_var.get() + " ✓")
                result_label.configure(foreground='green')
            else:
                self.validation_regex_result_var.set(self.validation_regex_result_var.get() + " ✗")
                result_label.configure(foreground='red')

    def show_equivalent_afd(self):
        """Muestra y guarda automáticamente el AFD equivalente"""
        validator_type = self.validator_type_var.get()
        
        if not validator_type:
            messagebox.showerror("Error", "Seleccione un tipo de validación primero")
            return
        
        try:
            # Crear el AFD equivalente
            afd = self.create_equivalent_afd(validator_type)
            
            # Convertir a formato JSON
            afd_json = {
                "alphabet": sorted(list(afd.alphabet)),
                "states": [state.name for state in afd.states],
                "initial_state": afd.initial_state.name if afd.initial_state else "",
                "final_states": [state.name for state in afd.final_states],
                "transitions": {
                    f"{from_state.name},{symbol}": to_state.name
                    for (from_state, symbol), to_state in afd.transitions.items()
                }
            }
            
            # Generar nombre de archivo automático
            import time
            filename = f"AFD_Equivalente_{validator_type.replace(' ', '_')}_{int(time.time())}.afd"
            
            # Guardar automáticamente
            with open(filename, 'w') as f:
                json.dump(afd_json, f, indent=2)
            
            # Mostrar en ventana emergente
            top = tk.Toplevel()
            top.title(f"AFD Equivalente para {validator_type}")
            top.geometry("700x500")
            
            # Frame principal
            main_frame = ttk.Frame(top)
            main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Mensaje de guardado
            ttk.Label(main_frame, 
                    text=f"El AFD equivalente se ha guardado como:\n{filename}",
                    font=('Arial', 10, 'bold')).pack(pady=5)
            
            # Texto con el AFD en formato JSON
            json_text = scrolledtext.ScrolledText(main_frame, width=80, height=20)
            json_text.pack(fill=tk.BOTH, expand=True)
            
            # Insertar el JSON formateado
            json_str = json.dumps(afd_json, indent=2)
            json_text.insert(tk.END, json_str)
            
            # Botones adicionales
            button_frame = ttk.Frame(main_frame)
            button_frame.pack(fill=tk.X, pady=5)
            
            def open_file():
                try:
                    import os
                    import platform
                    if platform.system() == "Windows":
                        os.startfile(filename)
                    elif platform.system() == "Darwin":
                        os.system(f"open {filename}")
                    else:
                        os.system(f"xdg-open {filename}")
                except Exception as e:
                    messagebox.showerror("Error", f"No se pudo abrir el archivo: {str(e)}")
            
            ttk.Button(button_frame, text="Abrir archivo", command=open_file).pack(side=tk.LEFT, padx=5)
            
            def copy_to_clipboard():
                self.clipboard_clear()
                self.clipboard_append(json_str)
                messagebox.showinfo("Copiado", "El AFD se ha copiado al portapapeles")
            
            ttk.Button(button_frame, text="Copiar JSON", command=copy_to_clipboard).pack(side=tk.LEFT, padx=5)
            
            def save_as():
                new_path = filedialog.asksaveasfilename(
                    defaultextension=".afd",
                    filetypes=[("AFD Files", "*.afd"), ("All Files", "*.*")],
                    initialfile=filename
                )
                if new_path:
                    try:
                        import shutil
                        shutil.copyfile(filename, new_path)
                        messagebox.showinfo("Éxito", f"Archivo guardado como:\n{new_path}")
                    except Exception as e:
                        messagebox.showerror("Error", f"No se pudo guardar: {str(e)}")
            
            ttk.Button(button_frame, text="Guardar como...", command=save_as).pack(side=tk.LEFT, padx=5)
            
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo generar el AFD equivalente:\n{str(e)}")

    def show_image_window(self, image_path):
        """Muestra la imagen del AFD en una ventana con zoom y scroll"""
        window = tk.Toplevel()
        window.title("Diagrama del AFD Equivalente")
        
        try:
            # Cargar la imagen
            img = tk.PhotoImage(file=image_path)
            
            # Frame principal
            main_frame = ttk.Frame(window)
            main_frame.pack(fill=tk.BOTH, expand=True)
            
            # Canvas con scrollbars
            canvas = tk.Canvas(main_frame)
            scroll_x = ttk.Scrollbar(main_frame, orient="horizontal", command=canvas.xview)
            scroll_y = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
            canvas.configure(xscrollcommand=scroll_x.set, yscrollcommand=scroll_y.set)
            
            scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
            scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
            canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            
            # Mostrar la imagen
            canvas.create_image(0, 0, anchor=tk.NW, image=img)
            canvas.config(scrollregion=canvas.bbox("all"))
            
            # Mantener referencia a la imagen
            canvas.image = img
            
            # Controles de zoom
            zoom_frame = ttk.Frame(window)
            zoom_frame.pack(fill=tk.X)
            
            def zoom_in():
                nonlocal img
                img = img.zoom(2, 2)
                canvas.create_image(0, 0, anchor=tk.NW, image=img)
                canvas.config(scrollregion=canvas.bbox("all"))
            
            def zoom_out():
                nonlocal img
                img = img.subsample(2, 2)
                canvas.create_image(0, 0, anchor=tk.NW, image=img)
                canvas.config(scrollregion=canvas.bbox("all"))
            
            ttk.Button(zoom_frame, text="Zoom (+)", command=zoom_in).pack(side=tk.LEFT)
            ttk.Button(zoom_frame, text="Zoom (-)", command=zoom_out).pack(side=tk.LEFT)
            
            # Ajustar tamaño inicial
            window.geometry("800x600")
            
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo cargar el diagrama:\n{str(e)}")
            window.destroy()
        
if __name__ == "__main__":
    app = AFDSimulator()
    app.mainloop()