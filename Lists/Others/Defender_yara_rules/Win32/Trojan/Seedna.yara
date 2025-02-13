rule Trojan_Win32_Seedna_A_2147685292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Seedna.A"
        threat_id = "2147685292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Seedna"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3f 25 73 3d 25 73 26 25 73 3d 25 6c 64 26 25 73 3d 25 64 26 25 73 3d 25 [0-2] 26 25 73 3d 25 73 26 56 65 72 3d 53 25 73}  //weight: 2, accuracy: Low
        $x_2_2 = {0f b6 10 0f b6 48 01 8b f2 83 e6 0f 8b d9 c1 e6 02 c1 e9 06 0b ce}  //weight: 2, accuracy: High
        $x_2_3 = {8d 04 cd ff ff ff ff 99 6a 18 5b f7 fb 8d 04 85 04 00 00 00 39 45 14 0f 8c 8e 02 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Seedna_A_2147685292_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Seedna.A"
        threat_id = "2147685292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Seedna"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "{E07DB02C-387E-43b2-A6F2-C59B4934B7D6}" wide //weight: 2
        $x_2_2 = "SendDataToDriver" ascii //weight: 2
        $x_2_3 = {2e 64 6c 6c 00 43 6f 6e 66 44 65 6c 65 74 65 00 43 6f 6e 66 52 65 61 64 00 43 6f 6e 66 57 72 69 74 65}  //weight: 2, accuracy: High
        $x_2_4 = {66 39 1a 74 14 8b ca 8a 09 88 8c 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

