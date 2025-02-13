rule TrojanDropper_Win32_Hesperbot_A_2147683046_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Hesperbot.A"
        threat_id = "2147683046"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Hesperbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_12_1 = "_hesperus_core_entry" ascii //weight: 12
        $x_8_2 = {64 72 6f 70 70 65 72 5f 78 38 36 2e 62 69 6e 00 5f 63 6f 72 65 5f 65 6e 74 72 79 40 34}  //weight: 8, accuracy: High
        $x_8_3 = {66 89 04 4b 41 3b 4d fc 72 c6 33 c0 57 66 89 04 4b c7 45 fc 01 00 00 00 e8}  //weight: 8, accuracy: High
        $x_8_4 = {8b c7 c1 e0 0b 33 c7 8b 7d f4 89 4d f4 8b 4d fc 89 4d f0 c1 e9 0b 33 c8 c1 e9 08 33 c8 31 4d fc 6a 04}  //weight: 8, accuracy: High
        $x_2_5 = "InstallDate" ascii //weight: 2
        $x_2_6 = "DigitalProductId" ascii //weight: 2
        $x_2_7 = "MachineGuid" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_8_*) and 3 of ($x_2_*))) or
            ((3 of ($x_8_*))) or
            ((1 of ($x_12_*) and 1 of ($x_8_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 2 of ($x_8_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Hesperbot_B_2147684597_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Hesperbot.B"
        threat_id = "2147684597"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Hesperbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 64 72 6f 70 70 65 72 5f 78 38 36 2e 62 69 6e 00 5f 63 6f 72 65 5f 65 6e 74 72 79 40 34}  //weight: 1, accuracy: High
        $x_1_2 = {03 d8 8b 53 20 8b 4b 24 57 8b 7b 1c 03 d0 03 c8 03 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

