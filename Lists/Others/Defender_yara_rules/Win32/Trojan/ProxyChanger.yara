rule Trojan_Win32_ProxyChanger_D_2147681402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProxyChanger.D"
        threat_id = "2147681402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProxyChanger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 61 6e 69 72 6f 73 61 2e 63 6f 6d 2f 69 6e 63 6c 75 64 65 73 2f 61 72 65 6e 61 2d 69 6e 66 65 63 74 2f 63 6f 6e 74 61 5f 69 6e 66 65 63 74 73 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {32 30 30 2e 39 38 2e 31 34 39 2e 36 36 2f [0-64] 2e 70 61 63 00}  //weight: 1, accuracy: Low
        $x_1_3 = "POST /includes/arena-infect/conta_infects.php HTTP/1.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ProxyChanger_GNE_2147924651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProxyChanger.GNE!MTB"
        threat_id = "2147924651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProxyChanger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {50 53 51 56 8b 75 ?? 8b 4d ?? c1 e9 ?? 8b 45 ?? 8b 5d ?? 85 c9 ?? ?? 31 06 01 1e 83 c6 ?? 49 eb ?? 5e 59 5b 58 c9 c2 ?? ?? 72 ?? cb 35 9d}  //weight: 5, accuracy: Low
        $x_5_2 = {e5 ec bb e2 f8 35 f3 42 69 7b cb 41 7f 6b 36 1c 42 47 a3 4f ba 9e f5 8b 29 b5 95 b3 0d 12 e7 31 d2 78 4b ea}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

