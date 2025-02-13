rule HackTool_Win64_DumpLsass_C_2147786198_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/DumpLsass.C"
        threat_id = "2147786198"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "DumpLsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $n_10_1 = "\\ProgramData\\Microsoft\\AzureWatson\\0\\procdump" wide //weight: -10
        $n_10_2 = {2d 00 6a 00 20 00 [0-4] 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 57 00 45 00 52 00 5c 00 52 00 65 00 70 00 6f 00 72 00 74 00 51 00 75 00 65 00 75 00 65 00}  //weight: -10, accuracy: Low
        $x_10_3 = "\\procdump64.exe" wide //weight: 10
        $x_5_4 = "-m" wide //weight: 5
        $x_5_5 = "/m" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win64_DumpLsass_I_2147799241_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/DumpLsass.I"
        threat_id = "2147799241"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "DumpLsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\dump64.exe" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_DumpLsass_C_2147811846_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/DumpLsass.C!Ofn"
        threat_id = "2147811846"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "DumpLsass"
        severity = "High"
        info = "Ofn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $n_10_1 = "\\ProgramData\\Microsoft\\AzureWatson\\0\\procdump" wide //weight: -10
        $n_10_2 = {2d 00 6a 00 20 00 [0-4] 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 57 00 45 00 52 00 5c 00 52 00 65 00 70 00 6f 00 72 00 74 00 51 00 75 00 65 00 75 00 65 00}  //weight: -10, accuracy: Low
        $x_10_3 = {5c 00 70 00 72 00 6f 00 63 00 64 00 75 00 6d 00 70 00 00 00}  //weight: 10, accuracy: High
        $x_5_4 = "-m" wide //weight: 5
        $x_5_5 = "/m" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

