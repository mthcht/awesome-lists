rule Trojan_Win64_RollerCoaster_D_2147961635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RollerCoaster.D!dha"
        threat_id = "2147961635"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RollerCoaster"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GotoLineCol.exe" ascii //weight: 2
        $x_1_2 = "C:\\WINDOWS\\\\GotoLineCol.ini" wide //weight: 1
        $x_1_3 = "boot.ini|" ascii //weight: 1
        $x_1_4 = {47 65 6e 65 72 61 6c 00 43 6f 6e 74 65 6e 74 00 4f 66 66 73 65 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

