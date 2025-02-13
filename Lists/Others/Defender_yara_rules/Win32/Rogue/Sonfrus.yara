rule Rogue_Win32_Sonfrus_164812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Sonfrus"
        threat_id = "164812"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Sonfrus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pouvoir supprimer les virus " ascii //weight: 1
        $x_1_2 = "Les codes sont invalides " ascii //weight: 1
        $x_1_3 = {4c 69 73 74 56 69 72 75 73 14}  //weight: 1, accuracy: High
        $x_1_4 = {26 63 6f 64 65 38 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {57 6f 72 6d 2e 42 61 67 67 6c 65 2e 43 50 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

