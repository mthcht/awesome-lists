rule Trojan_Win32_CryInfector_MBFH_2147898114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryInfector.MBFH!MTB"
        threat_id = "2147898114"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryInfector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 2b 33 71 b5 02 00 00 00 c0 2f 40 00 d4}  //weight: 10, accuracy: High
        $x_1_2 = {2b 40 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 f0 25 40 00 b0 25 40 00 00 16 40 00 78 00 00 00 83 00 00 00 8e}  //weight: 1, accuracy: High
        $x_1_3 = {4f 66 66 69 63 65 53 61 66 65 00 4f 66 66 69 63 65 53 61 66 65 00 00 4f 66 66 69 63 65 53 61 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

