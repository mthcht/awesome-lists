rule Trojan_Win32_ShardLoader_KVX_2147973274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShardLoader.KVX!MTB"
        threat_id = "2147973274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShardLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 25 49 92 24 f7 e7 8b c7 2b c2 d1 e8 03 c2 c1 e8 04 8d 0c c5 00 00 00 00 2b c8 8b c7 c1 e1 02 2b c1 8a 44 05 e0 30 04 37 47 3b fb}  //weight: 1, accuracy: High
        $x_1_2 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 49 44 4d 5c 6c 6f 67 73 5c 4d 65 64 69 75 6d 49 6e 73 74 53 74 61 72 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "SolidPDFCreator.dll" ascii //weight: 1
        $x_1_4 = "GetSPApp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

