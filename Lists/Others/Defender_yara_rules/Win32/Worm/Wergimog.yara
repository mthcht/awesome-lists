rule Worm_Win32_Wergimog_A_2147644653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Wergimog.A"
        threat_id = "2147644653"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Wergimog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {74 68 61 74 62 69 67 66 75 63 6b 69 6e 67 6e 69 67 67 65 72 00}  //weight: 10, accuracy: High
        $x_10_2 = "%s\\nig_%s." ascii //weight: 10
        $x_10_3 = "%s\\ngr_%s." ascii //weight: 10
        $x_10_4 = "pipe\\ngrisu" ascii //weight: 10
        $x_1_5 = {49 6e 66 65 63 74 65 64 20 44 72 69 76 65 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {49 6e 66 65 63 74 65 64 20 44 72 69 76 65 20 25 63 3a 5c 00}  //weight: 1, accuracy: High
        $x_1_7 = "Usb Infected" ascii //weight: 1
        $x_1_8 = {48 54 54 50 20 41 74 74 61 63 6b 20 41 63 74 69 76 65 21 00}  //weight: 1, accuracy: High
        $x_1_9 = {55 44 50 20 41 74 74 61 63 6b 20 41 63 74 69 76 65 21 00}  //weight: 1, accuracy: High
        $x_1_10 = {55 64 70 20 46 6c 6f 6f 64 20 41 63 74 69 76 65 21 00}  //weight: 1, accuracy: High
        $x_1_11 = {53 73 79 6e 20 46 6c 6f 6f 64 20 41 63 74 69 76 65 21 00}  //weight: 1, accuracy: High
        $x_1_12 = "LNK Infected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Wergimog_KA_2147851487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Wergimog.KA!MTB"
        threat_id = "2147851487"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Wergimog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff 75 10 33 ff e8 ?? ?? ?? ?? 85 c0 59 76 15 8b 45 10 50 8a 0c 07 30 0c 1e 47 e8 ?? ?? ?? ?? 3b f8 59 72 eb 8a 04 1e f6 d0 88 04 1e 46 3b 75 0c 72 ce}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

