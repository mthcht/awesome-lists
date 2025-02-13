rule TrojanDropper_Win32_Tukrina_A_2147724968_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Tukrina.A!dha"
        threat_id = "2147724968"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Tukrina"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\%s.tlb" ascii //weight: 1
        $x_1_2 = "%s\\%s.ini" ascii //weight: 1
        $x_1_3 = "%s\\%s.dat" ascii //weight: 1
        $x_2_4 = {52 75 6e 44 6c 6c 33 32 2e 65 78 65 20 22 00}  //weight: 2, accuracy: High
        $x_2_5 = {22 20 53 74 61 72 74 52 6f 75 74 69 6e 65 00}  //weight: 2, accuracy: High
        $x_2_6 = {22 2c 49 6e 73 74 61 6c 6c 52 6f 75 74 69 6e 65 20 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

