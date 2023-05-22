# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information
import alabaster

project = 'flask-pg-session'
copyright = '2023, Giuseppe Papallo'
author = 'Giuseppe Papallo'
release = '0.1.0'


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "alabaster",
    # "myst_parser"
]
autosummary_generate = True  # Turn on sphinx.ext.autosummary
autodoc_default_options = {
    "show-inheritance": False,
    # "members": True,
    "member-order": "bysource",
    # "special-members": "__init__",
    # "undoc-members": True,
    "exclude-members": "__weakref__",
}
autoclass_content = "init"

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = []


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "alabaster"
html_theme_path = [alabaster.get_path()]

html_sidebars = {
    "**": [
        "about.html",
        "navigation.html",
        "relations.html",
        "searchbox.html",
        # "donate.html",
    ]
}

html_theme_options = {
    "code_font_family": '"SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace',
    "description": "A PostgreSQL-based server-side session extension for Flask.",
    "code_font_size": "0.8em",
    "fixed_sidebar": True,
    "github_banner": False,
    "github_button": True,
    "github_type": "star",
    "github_user": "giuppep",
    "github_repo": "flask-pg-session",
    "extra_nav_links": {
        "Flask": "https://flask.palletsprojects.com/",
        "Flask-Session": "https://flasksession.readthedocs.io/en/latest/"
    },
}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
# html_static_path = ["_static"]

source_suffix = {
    '.rst': 'restructuredtext',
    '.md': 'markdown',
}