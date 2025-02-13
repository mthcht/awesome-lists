rule Worm_Win32_Opanki_2147598002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Opanki"
        threat_id = "2147598002"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Opanki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "_Oscar_StatusNotify" ascii //weight: 1
        $x_1_2 = "_Oscar_IconBtn" ascii //weight: 1
        $x_2_3 = {55 68 23 4e 00 00 68 11 01 00 00 57 ff 15}  //weight: 2, accuracy: High
        $x_3_4 = {68 8b 00 00 00 68 11 01 00 00 ff 74 [0-64] 6a 25 68 00 01 00 00}  //weight: 3, accuracy: Low
        $x_3_5 = {41 49 4d 5f 49 4d 65 73 73 61 67 65 [0-5] 5f 4f 73 63 61 72 5f 54 72 65 65}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Opanki_CW_2147600071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Opanki.CW"
        threat_id = "2147600071"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Opanki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AIM_IMessage" ascii //weight: 1
        $x_1_2 = "_Oscar_Tree" ascii //weight: 1
        $x_1_3 = "_Oscar_StatusNotify" ascii //weight: 1
        $x_1_4 = "_AimAd" ascii //weight: 1
        $x_1_5 = "WndAte32Class" ascii //weight: 1
        $x_1_6 = {57 6a 00 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 8b f0 56 ff d7 85 c0 74 ?? 6a 00 68 23 4e 00 00 68 11 01 00 00 56 ff 15 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 33 f6}  //weight: 1, accuracy: Low
        $x_1_7 = {52 ff d7 8b f0 56 ff d3 85 c0 74 ?? 56 ff 15 ?? ?? ?? ?? 3d 99 01 00 00 75 ?? 6a 00 6a 00 68 01 02 00 00 56 ff d5 6a 00 6a 00 68 02 02 00 00 56 ff d5 33 f6 56 ff d3 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

