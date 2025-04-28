rule Trojan_Win32_Mofei_PGM_2147940188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mofei.PGM!MTB"
        threat_id = "2147940188"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mofei"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2e 64 61 74 61 00 00 00 d4 14 00 00 00 40 00 00 00 06 00 00 00 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
        $x_3_2 = {77 6d 63 73 65 72 76 2e 65 78 65 00 24 73 5c 73 79 73 74 65 6d 33 32 5c 26 73 41 00 4d 54 42 54 52 2d 44 57 45 00 00 00 2d 70 00 00 2d 76 00 00 2d 64}  //weight: 3, accuracy: High
        $x_5_3 = {5c 61 76 70 2e 65 78 65 00 00 00 00 4b 49 53 38 00 4b 41 56 38 00 4b 49 53 37 00 4b 41 56 37 00 53 4f 46 54 57 41 52 45 5c 4b 61 73 70 65 72 73 6b 79 4c 61 62 5c 53 65 74 75 70 46 6f 6c 64 65 72 73}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

