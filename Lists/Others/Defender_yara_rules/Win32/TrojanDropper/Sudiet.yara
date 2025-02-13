rule TrojanDropper_Win32_Sudiet_A_2147610329_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sudiet.A"
        threat_id = "2147610329"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sudiet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a c8 80 c1 ?? 30 88 ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 72 ed b8}  //weight: 4, accuracy: Low
        $x_1_2 = "\\TDKD" wide //weight: 1
        $x_1_3 = "tdssserv" wide //weight: 1
        $x_1_4 = "tdssdata" wide //weight: 1
        $x_1_5 = "tdsscmd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

