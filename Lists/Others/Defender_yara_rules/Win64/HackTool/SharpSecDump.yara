rule HackTool_Win64_SharpSecDump_2147763349_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/SharpSecDump!lsa"
        threat_id = "2147763349"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "SharpSecDump"
        severity = "High"
        info = "lsa: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-SharpSecDump Info-" wide //weight: 1
        $x_1_2 = "[*] LSA Secrets" wide //weight: 1
        $x_1_3 = "[*] Parsing SAM hive" wide //weight: 1
        $x_1_4 = "[*] Parsing SECURITY hive" wide //weight: 1
        $x_1_5 = "LMPASSWORD" wide //weight: 1
        $x_1_6 = "- outputing raw secret" wide //weight: 1
        $x_1_7 = "SharpSecDump.exe -target=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

