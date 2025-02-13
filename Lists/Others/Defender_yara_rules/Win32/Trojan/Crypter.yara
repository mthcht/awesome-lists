rule Trojan_Win32_Crypter_DC_2147797975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crypter.DC!MTB"
        threat_id = "2147797975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {19 03 00 e9 30 00 04 00 00 de 39 00 00 e9 00 4b 06 00 e9 9e 00 02 00 00 28 eb 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

