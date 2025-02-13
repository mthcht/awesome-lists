rule TrojanDropper_Win32_Donise_A_2147611155_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Donise.A"
        threat_id = "2147611155"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Donise"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {e8 0f 00 00 00 26 80 ac c8 33 db 64 8f 03 59 90}  //weight: 2, accuracy: High
        $x_2_2 = {75 07 c7 45 e4 12 ef cd ab 8b 75 08}  //weight: 2, accuracy: High
        $x_1_3 = {72 73 79 6e 63 69 6e 69 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

