rule ole_doc_header : doc {
  meta:
    description = "DOC (OLE) container header"
  condition:
    // OLE magic: D0 CF 11 E0 A1 B1 1A E1 (little-endian 상수 표기)
    uint64(0) == 0xE11AB1A1E011CFD0
}

rule zip_ooxml_header : docx {
  meta:
    description = "OOXML (DOCX/DOCM/ZIP) container header"
  condition:
    // PK\x03\x04
    uint32(0) == 0x04034B50
}

rule rtf_header : doc {
  meta:
    description = "RTF header"
  strings:
    $rtf = "{\\rtf" ascii
  condition:
    $rtf at 0
}

rule pdf_header : pdf {
  meta:
    description = "PDF header"
  strings:
    $pdf = "%PDF-" ascii
  condition:
    $pdf at 0
}

rule macro_or_ransom_hint : doc macro {
  meta:
    description = "Office macro trigger + ransom/behavior hint"
  strings:
    $macro1 = "AutoOpen" nocase ascii wide
    $macro2 = "Document_Open" nocase ascii wide
    $ps     = "powershell" nocase ascii wide
    $note   = "All your files have been encrypted" nocase ascii
    $vbabin = "vbaProject.bin" ascii
  condition:
    (uint64(0) == 0xE11AB1A1E011CFD0 or uint32(0) == 0x04034B50) and
    (any of ($macro*) or $vbabin) and ($ps or $note)
}

rule pe_header_basic : pe {
  meta:
    description = "PE (MZ) header"
  condition:
    uint16(0) == 0x5A4D
}

rule pe_common_strings : pe {
  meta:
    description = "Common PE stub/API/AES/URL hints"
  strings:
    $dos = "This program cannot be run in DOS mode" ascii wide
    $api = "VirtualAlloc" ascii wide
    $aes = /AES(128|192|256)/ nocase
    $url = /https?:\/\// ascii
  condition:
    uint16(0) == 0x5A4D and any of them
}

rule html_like_doc : doc {
  meta:
    description = "HTML content saved as .doc"
  strings:
    $h1 = "<!DOCTYPE html" nocase ascii
    $h2 = "<html" nocase ascii
  condition:
    any of them and ext_filename matches /\.doc$/i
}

rule word2003_xml_doc : doc {
  meta:
    description = "Word 2003 XML content saved as .doc"
  strings:
    $xml = "<?xml" ascii
    $wml = "<w:wordDocument" nocase ascii
  condition:
    any of them and ext_filename matches /\.doc$/i
}

rule doc_extension_fallback : doc fallback {
  meta:
    description = "filename *.doc (content-agnostic)"
  condition:
    ext_filename matches /\.doc$/i
}

rule ping : smoke {
  meta:
    description = "pipeline check"
  condition:
    true
}
