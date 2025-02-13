rule Trojan_Win32_Detplock_RPX_2147845774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Detplock.RPX!MTB"
        threat_id = "2147845774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Detplock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 fb 4f 31 11 29 ff 81 ef 01 00 00 00 01 fb 41 81 eb 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 12 89 ff 81 e2 ff 00 00 00 09 df 29 db 29 db 46}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

