rule Trojan_Win32_DLLHijack_DF_2147939451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLHijack.DF!MTB"
        threat_id = "2147939451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 34 0f 02 de 8a 14 1f 88 14 0f 88 34 1f 02 d6 0f b6 d2 8a 14 17 8a 0c 06 32 ca 5a 88 0c 02}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DLLHijack_RPA_2147944575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLHijack.RPA!MTB"
        threat_id = "2147944575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 ec 33 c6 45 ed 38 c6 45 ee 2e c6 45 ef 31 c6 45 f0 38 c6 45 f1 31 c6 45 f2 2e c6 45 f3 34 c6 45 f4 32 c6 45 f5 2e c6 45 f6 31 c6 45 f7 32 c6 45 f8 37 c6 45 f9 00 c6 85 28 fc ff ff 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

