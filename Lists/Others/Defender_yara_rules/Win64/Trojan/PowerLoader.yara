rule Trojan_Win64_PowerLoader_GA_2147932969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PowerLoader.GA!MTB"
        threat_id = "2147932969"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PowerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b d2 41 0f b6 0b 41 8b c0 49 ff c3 48 33 c8 0f b6 c1 41 8b c8 44 8b 04 83 c1 e9 08 44 33 c1 48 ff ca 75 de}  //weight: 2, accuracy: High
        $x_1_2 = {4c 8b f9 48 8d 4c 24 38 45 8d 45 30 33 d2 41 8b f9 41 8b f5 4c 89 6c 24 30}  //weight: 1, accuracy: High
        $x_2_3 = {41 ff c1 33 d2 41 8b c0 41 f7 f1 30 11 48 ff c1 45 3b ca 72 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_PowerLoader_CH_2147955875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PowerLoader.CH!MTB"
        threat_id = "2147955875"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PowerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Global\\%s%x" ascii //weight: 2
        $x_2_2 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; InfoPath.1)" ascii //weight: 2
        $x_2_3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36" ascii //weight: 2
        $x_2_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_2_5 = "inject" ascii //weight: 2
        $x_2_6 = "chrome.exe" ascii //weight: 2
        $x_2_7 = "opera.exe" ascii //weight: 2
        $x_2_8 = "msedge.exe" ascii //weight: 2
        $x_2_9 = "brave.exe" ascii //weight: 2
        $x_2_10 = "/create /sc minute /tn" ascii //weight: 2
        $x_2_11 = "13poh9EisZfuzCQgianG1UDdmUdfCRKLjS" ascii //weight: 2
        $x_2_12 = "LchC1r2kbT5NQ9RhWrD5wwp1JUjuBNvYHq" ascii //weight: 2
        $x_2_13 = "TVGX9CSJPxkUyLJLAQVi8ifLTvukxdZACn" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PowerLoader_FAC_2147972065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PowerLoader.FAC!MTB"
        threat_id = "2147972065"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PowerLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b7 c1 66 f7 d0 66 83 e0 20 66 23 cf 66 2b c8 41 0f b6 c2 32 c1 0f b6 c0 42 0f b6 14 38 41 8b ca c1 e1 18 41 8b c2 48 c1 e8 ?? 48 0b c8 48 8b c1 48 23 c2 4c 8d 04 00 48 33 ca 4e 8d 14 01 49 8b ca 48 f7 d1 48 03 c9 4b 8d 04 00 23 c8 45 33 d0 44 2b d1 41 0f b7 09}  //weight: 5, accuracy: Low
        $x_1_2 = "[!] Failed to fetch install command from server" ascii //weight: 1
        $x_1_3 = "[*] Installing scheduled task..." ascii //weight: 1
        $x_1_4 = "[*] Installing Run key..." ascii //weight: 1
        $x_1_5 = "%s Persistence %s" ascii //weight: 1
        $x_1_6 = "[*] Executing command..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

