# Simulador de Autómatas Finitos y Expresiones Regulares

## Descripción
Aplicación gráfica para diseñar, simular y analizar Autómatas Finitos (AFD/NFA) con conversión a Expresiones Regulares. Incluye validadores predefinidos para emails, teléfonos, URLs, fechas y contraseñas.

## Características
- Interfaz gráfica con pestañas organizadas
- Visualización de autómatas con Graphviz
- Conversión NFA ↔ DFA
- Transformación AFD → Expresión Regular
-  Validación con ER predefinidas
- Guardado/carga en formatos JSON y JFLAP

## Requisitos
- Python 3.8+
- Bibliotecas:
- tkinter
-graphviz

## Uso
1. Ejecutar `python practica4.py`
2. Navegar por las pestañas:
 - **Definición**: Crear estados/transiciones
 - **Simulación**: Probar cadenas paso a paso
 - **Conversión**: Transformar AFD a ER
 - **Herramientas**: Generar subcadenas/cerraduras
 - **Validadores**: Probar patrones comunes

## Ejemplos
- Cargar autómata desde archivo .jff
- Convertir NFA a DFA automáticamente
- Generar expresión regular equivalente
- Validar formato de emails/contraseñas
