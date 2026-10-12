rule Trojan_Win32_OverloadRAT_MZC_2147980130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OverloadRAT.MZC!MTB"
        threat_id = "2147980130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OverloadRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 67 6f 31 2e 32 36 2e 32 f1 09 30 77 af 0c 92 74 08 02 41 e1 c1 07 e6 d6 18 e6 70 61 74 68 09 6f 76 65 72 6c 6f 72 64 2d 63 6c 69 65 6e 74 2f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

