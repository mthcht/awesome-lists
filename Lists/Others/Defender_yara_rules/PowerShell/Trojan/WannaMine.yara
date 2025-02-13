rule Trojan_PowerShell_WannaMine_A_2147725599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/WannaMine.A"
        threat_id = "2147725599"
        type = "Trojan"
        platform = "PowerShell: "
        family = "WannaMine"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/info6.ps1')}else{IEX(New-Object Net.WebClient).DownloadString('" wide //weight: 1
        $x_1_2 = "\\y1.bat && SCHTASKS /create /RU System /SC DAILY /TN yastcat " wide //weight: 1
        $x_1_3 = "'SCM Event Filter')))) {IEX(New-Object Net.WebClient).DownloadString" wide //weight: 1
        $x_1_4 = "JABzAHQAaQBtAGUAPQBbAEUAbgB2AGkAcgBvAG4AbQBlAG4AdABdADoAOgBUAGkAYwBrAEMAbwB1AG4" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_PowerShell_WannaMine_B_2147725757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/WannaMine.B"
        threat_id = "2147725757"
        type = "Trojan"
        platform = "PowerShell: "
        family = "WannaMine"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 00 65 00 78 00 28 00 6e 00 65 00 77 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 29 00 2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 ?? ?? ?? ?? ?? ?? ?? [0-9] 2f 00 69 00 6e 00 66 00 6f 00 ?? 2e 00 70 00 73 00 31 00 22 00}  //weight: 1, accuracy: Low
        $x_1_2 = "sch`tas`ks /delete /tn yastcat /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

