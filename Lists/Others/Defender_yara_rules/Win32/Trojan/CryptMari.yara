rule Trojan_Win32_CryptMari_SA_2147742813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptMari.SA!MTB"
        threat_id = "2147742813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptMari"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 99 f7 f9 8a 04 1a 8b 55 f8 30 04 16 46 3b f7 7c}  //weight: 1, accuracy: High
        $x_1_2 = {5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 65 73 6b 74 6f 70 5c 63 72 70 74 72 5c 62 61 73 65 5c [0-2] 5c 73 74 75 62 5c 52 65 6c 65 61 73 65 5c 73 74 75 62 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

