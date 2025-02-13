rule Trojan_Win32_Xiaoba_A_2147726888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Xiaoba.gen!A"
        threat_id = "2147726888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Xiaoba"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "var miner = new CoinHive.Anonymous('yuNWeGn9GWL72dONBX9WNEj1aVHxg49E');" ascii //weight: 2
        $x_1_2 = {3a 5c 00 2a 2e 65 78 65 00 2a 2e 63 6f 6d 00 2a 2e}  //weight: 1, accuracy: High
        $x_1_3 = "\\ZhuDongFangYu.exe" ascii //weight: 1
        $x_1_4 = {25 73 5c 25 73 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_5 = {6a 07 50 6a 00 ff 15 ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 8d 54 24 ?? 51 52 8d 44 24 ?? 68 ?? ?? ?? ?? 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Xiaoba_GPA_2147900381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Xiaoba.GPA!MTB"
        threat_id = "2147900381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Xiaoba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {68 01 00 00 00 68 02 42 40 00 68 02 42 40 00 8d 45 fc 50 ff 15}  //weight: 4, accuracy: High
        $x_4_2 = {eb d3 c3 4d 44 35 b2 e9 bf b4 c6 f7 20 b2 e9 bf b4 cf c2 b3 cc d0 f2 4d 44 35 d3 d0 c4 be d3 d0 b8 c4 b1 e4 00 4d 44 35 a3 ba 00 35 44 4d}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

