rule Trojan_Win64_MulDrop_NM_2147948816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MulDrop.NM!MTB"
        threat_id = "2147948816"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MulDrop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8d 05 f7 da 09 00 48 89 04 24 e8 4e f0 01 00 45 0f 57 ff 4c 8b 35 f3 1e 1a 00 65 4d 8b 36 4d 8b 36 48 8b 44 24 08 48 8b 40 30 ff 88 3c 02 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {4c 89 74 24 08 49 8b 46 30 83 b8 3c 02 00 00 00 66 90 75 22 48 8d 05 f7 da 09 00 48 89 04 24}  //weight: 1, accuracy: High
        $x_1_3 = "ResumeThread" ascii //weight: 1
        $x_1_4 = "victim" ascii //weight: 1
        $x_1_5 = "kill" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

