rule TrojanSpy_Win32_AshamedWages_A_2147923568_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/AshamedWages.A!dha"
        threat_id = "2147923568"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "AshamedWages"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 77 08 ff 75 08 e8 13 ff ff ff 89 07 83 c7 0c 83 3f ff 75 eb}  //weight: 1, accuracy: High
        $x_1_2 = {ac 30 d0 aa c1 ca 08 e2 f7 61 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_AshamedWages_D_2147924189_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/AshamedWages.D!MTB"
        threat_id = "2147924189"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "AshamedWages"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {fe c3 8a 14 1f 00 d0 8a 0c 07 88 0c 1f 88 14 07 00 d1 8a 0c 0f 30 0e 46 ff 4d 14 75}  //weight: 5, accuracy: High
        $x_1_2 = {89 e5 6a 04 68 00 30 00 00 68 00 00 e0 06 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {f7 e2 3c 61 72 04 3c 7a 76 0d 2d 21 30 00 00 81 c2 21 30 00 00 eb e9 aa e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

