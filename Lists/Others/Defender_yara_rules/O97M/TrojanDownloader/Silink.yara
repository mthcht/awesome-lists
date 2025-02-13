rule TrojanDownloader_O97M_Silink_B_2147742774_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Silink.B"
        threat_id = "2147742774"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Silink"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c 6c 20 28 22 6d 73 68 74 61 20 68 74 74 70 73 3a 2f 2f 6c 6f 67 69 6e 2d 6d 61 69 6e 2e 62 69 67 77 6e 65 74 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 2f 76 69 65 77 2f 4d 73 67 [0-3] 2e 68 74 61 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Silink_C_2147742775_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Silink.C"
        threat_id = "2147742775"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Silink"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "malware" ascii //weight: 20
        $x_12_2 = "mbam.exe" ascii //weight: 12
        $x_12_3 = "WinDefend" ascii //weight: 12
        $x_12_4 = "McShield.exe" ascii //weight: 12
        $x_10_5 = "mshta.exe http" ascii //weight: 10
        $x_1_6 = "Shell (\"cmd.exe /c" ascii //weight: 1
        $x_1_7 = "wShell.run(\"\"cmd.exe /c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_12_*) and 1 of ($x_10_*))) or
            ((1 of ($x_20_*) and 1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_12_*))) or
            (all of ($x*))
        )
}

