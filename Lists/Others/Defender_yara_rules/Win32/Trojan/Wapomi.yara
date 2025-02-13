rule Trojan_Win32_Wapomi_A_2147899202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wapomi.A!MTB"
        threat_id = "2147899202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wapomi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 45 94 47 65 74 50 c7 45 98 72 6f 63 41 c7 45 9c 64 64 72 65 c7 45 a0 73 73}  //weight: 2, accuracy: High
        $x_2_2 = {c7 45 94 57 72 69 74 c7 45 98 65 46 69 6c c7 45 9c 65}  //weight: 2, accuracy: High
        $x_2_3 = {c7 45 94 43 6c 6f 73 c7 45 98 65 48 61 6e c7 45 9c 64 6c 65}  //weight: 2, accuracy: High
        $x_2_4 = {c7 45 94 57 69 6e 45 c7 45 98 78 65 63}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

