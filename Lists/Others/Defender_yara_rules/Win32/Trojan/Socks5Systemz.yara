rule Trojan_Win32_Socks5Systemz_ASO_2147907011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Socks5Systemz.ASO!MTB"
        threat_id = "2147907011"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Socks5Systemz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b f0 c7 44 24 08 98 82 02 10 8d 44 24 08 50 8d 4c 24 40}  //weight: 1, accuracy: High
        $x_1_2 = {8b f0 c7 44 24 0c 78 82 02 10 8d 44 24 0c 50 8d 4c 24 14}  //weight: 1, accuracy: High
        $x_1_3 = {c7 44 24 48 24 00 00 00 89 74 24 4c c7 44 24 64 0f 00 00 00 c7 44 24 60 00 00 00 00 c6 44 24 50 00 c7 44 24 3c f4 81 02 10 8d 44 24 3c c7 44 24 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

