rule Backdoor_Win32_Vharke_N_2147668292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Vharke.N"
        threat_id = "2147668292"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Vharke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Projekt1_Generated-10\\Projekt1.vbp" wide //weight: 1
        $x_1_2 = "\\Server\\Projekt1.vbp" wide //weight: 1
        $x_1_3 = "\\Shark\\" wide //weight: 1
        $x_1_4 = ".biz:555" wide //weight: 1
        $x_1_5 = ".net:555" wide //weight: 1
        $x_1_6 = "moo2.exe" wide //weight: 1
        $x_2_7 = "*.shark" wide //weight: 2
        $x_3_8 = "Hello AV-Companys, this is \"Backdoor." wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

