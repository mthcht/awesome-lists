rule Trojan_Win64_WinGO_BNK_2147849128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WinGO.BNK!MTB"
        threat_id = "2147849128"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WinGO"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 c7 40 08 02 00 00 00 48 8d 15 94 ea 01 00 48 89 10 48 8b 3d dc cb 49 00 48 8b 35 dd cb 49 00 48 8d 1d 07 f1 01 00 b9 06 00 00 00 31 c0 e8 82 95 f9 ff 48 8b 7c 24 50 48 89 5f 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

