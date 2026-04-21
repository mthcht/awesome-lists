rule Trojan_Win32_NetSupportRat_ANR_2147967394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetSupportRat.ANR!MTB"
        threat_id = "2147967394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetSupportRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {50 8d 44 24 4c 50 68 00 00 42 00 68 50 85 41 00 8d 84 24 88 02 00 00 68 00 02 00 00 50 e8 ?? ?? ?? ?? 83 c4 18 8d 84 24 70 01 00 00 50 68 04 01 00 00 ff 15 ?? ?? ?? ?? 8d 44 24 48 50 8d 84 24 74 01 00 00 50 68 64 85 41 00}  //weight: 3, accuracy: Low
        $x_2_2 = {50 68 80 83 41 00 8d 84 24 34 02 00 00 68 00 10 00 00 50 e8 ?? ?? ?? ?? 8d 84 24 3c 02 00 00 50 68 c8 83 41 00 e8 ?? ?? ?? ?? 6a 40 8d 44 24 54 c7 44 24 50 44 00 00 00 6a 00 50}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

