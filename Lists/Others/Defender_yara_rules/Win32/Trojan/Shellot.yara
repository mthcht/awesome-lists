rule Trojan_Win32_Shellot_YAA_2147906590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shellot.YAA!MTB"
        threat_id = "2147906590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shellot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 55 0c 28 14 39 41 3b c8 72}  //weight: 1, accuracy: High
        $x_1_2 = {8b c1 6a 02 99 5b f7 fb 85 d2 75 ?? 8b 45 ?? 8a 00 ff 45 fc eb ?? 8a 06 46 88 04 39 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

