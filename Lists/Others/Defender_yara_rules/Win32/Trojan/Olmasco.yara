rule Trojan_Win32_Olmasco_MA_2147900098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Olmasco.MA!MTB"
        threat_id = "2147900098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Olmasco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {4b 0f b6 4c 14 14 4b 8b da 86 e9 03 df 21 cb 8d 1c 10 83 eb 1a 30 2f 8d 5a 04 09 c3 b7 56 4b 47 b3 20 83 c3 7b 4d 0f 85}  //weight: 10, accuracy: High
        $x_1_2 = "Ejnkxnsooc" ascii //weight: 1
        $x_1_3 = "Uqnjqcaycj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

