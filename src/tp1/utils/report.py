"""Module de génération de rapports PDF."""
from fpdf import FPDF
import pygal
from pygal.style import DefaultStyle
import tempfile
import os


class Report:
    def __init__(self, capture, filename, summary):
        """
        Initialise le rapport.
        
        Args:
            capture: Instance de Capture avec les données
            filename: Nom du fichier PDF à générer
            summary: Résumé textuel de l'analyse
        """
        self.capture = capture
        self.filename = filename
        self.title = "RAPPORT D'ANALYSE DE TRAFIC RESEAU"
        self.summary = summary
        self.protocols = capture.get_all_protocols()
        self.pdf = FPDF()
        
    def generate(self, param: str) -> None:
        """
        Génère un graphique ou un tableau.
        
        Args:
            param: 'graph' pour graphique, 'array' pour tableau
        """
        if param == "graph":
            self._generate_graph()
        elif param == "array":
            self._generate_array()
    
    def _generate_graph(self) -> None:
        """Génère un graphique en barre des protocoles."""
        if not self.protocols:
            return
        
        bar_chart = pygal.Bar(
            title='Répartition des protocoles réseau',
            x_title='Protocoles',
            y_title='Nombre de paquets',
            style=DefaultStyle,
            width=800,
            height=400
        )
        
        for protocol, count in self.protocols.items():
            bar_chart.add(protocol, [count])
        
        temp_svg = tempfile.NamedTemporaryFile(suffix='.svg', delete=False)
        bar_chart.render_to_file(temp_svg.name)
        
        self.graph_path = temp_svg.name
    
    def _generate_array(self) -> None:
        """Génère un tableau des protocoles dans le PDF."""
        if not self.protocols:
            return
        
        self.pdf.add_page()
        self.pdf.set_font('Arial', 'B', 14)
        self.pdf.cell(0, 10, 'Tableau des protocoles', ln=True)
        self.pdf.ln(5)
        
        self.pdf.set_font('Arial', 'B', 12)
        self.pdf.cell(60, 10, 'Protocole', border=1)
        self.pdf.cell(60, 10, 'Nombre de paquets', border=1)
        self.pdf.cell(60, 10, 'Pourcentage', border=1)
        self.pdf.ln()
        
        self.pdf.set_font('Arial', '', 12)
        total = sum(self.protocols.values())
        
        for protocol, count in self.protocols.items():
            percentage = (count / total * 100) if total > 0 else 0
            self.pdf.cell(60, 10, protocol, border=1)
            self.pdf.cell(60, 10, str(count), border=1)
            self.pdf.cell(60, 10, f"{percentage:.1f}%", border=1)
            self.pdf.ln()
    
    def save(self, filename: str) -> None:
        """
        Génère et sauvegarde le rapport PDF complet.
        
        Args:
            filename: Nom du fichier PDF
        """
        self.pdf.add_page()
        self.pdf.set_font('Arial', 'B', 16)
        self.pdf.cell(0, 10, self.title, ln=True, align='C')
        self.pdf.ln(10)
        
        self.pdf.set_font('Courier', '', 9)
        
        for line in self.summary.split('\n'):
            if line.strip():
                clean_line = line[:90]
                self.pdf.cell(0, 4, clean_line, ln=True)
            else:
                self.pdf.ln(2)
        
        self.pdf.output(filename)
        
        if hasattr(self, 'graph_path') and os.path.exists(self.graph_path):
            os.unlink(self.graph_path)
        
        print(f"\nRapport PDF généré: {filename}")
