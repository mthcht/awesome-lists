rule Trojan_Win32_Foreign_DW_2147819504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Foreign.DW!MTB"
        threat_id = "2147819504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Foreign"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 08 c1 e9 08 33 d1 8b 45 08 8b 08 03 ca 03 4d 10 8b 55 0c 8b 02 2b c1 8b 4d 0c 89 01 8b 55 08 8b 45 0c 8b 08 89 0a 83 7d fc 14 75 02 eb 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Foreign_AFR_2147850636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Foreign.AFR!MTB"
        threat_id = "2147850636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Foreign"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 0c 33 c0 8d 4c 24 ?? 51 8d 54 24 ?? 52 50 50 68 00 01 00 00 50 50 50 57 50 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

