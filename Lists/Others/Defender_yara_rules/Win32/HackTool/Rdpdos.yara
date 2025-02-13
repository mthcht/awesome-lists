rule HackTool_Win32_Rdpdos_A_2147655472_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Rdpdos.A"
        threat_id = "2147655472"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Rdpdos"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "x03\\x99\\x99\\x13\\x0e\\x" wide //weight: 3
        $x_1_2 = "RDPKill" ascii //weight: 1
        $x_1_3 = "RDP gremlins" wide //weight: 1
        $x_1_4 = "Welcome to RDPKill (MS12-020)" wide //weight: 1
        $x_1_5 = "Mark DePalma" ascii //weight: 1
        $x_1_6 = "cmdKill" ascii //weight: 1
        $x_1_7 = "3389" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

