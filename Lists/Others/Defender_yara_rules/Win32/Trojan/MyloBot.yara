rule Trojan_Win32_MyloBot_RDB_2147838457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MyloBot.RDB!MTB"
        threat_id = "2147838457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MyloBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 0e 33 ca 81 e1 ff 00 00 00 c1 ea 08 33 14 8d ?? ?? ?? ?? 46 48 75 ?? 8b c7 8b da}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MyloBot_RDA_2147838555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MyloBot.RDA!MTB"
        threat_id = "2147838555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MyloBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" ascii //weight: 1
        $x_1_2 = "DisableAntiSpyware" ascii //weight: 1
        $x_2_3 = {0f b6 06 33 c1 c1 e9 08 0f b6 c0 33 8c 85 00 fc ff ff 46 83 ea 01}  //weight: 2, accuracy: High
        $x_2_4 = {0f b6 06 33 c1 c1 e9 08 0f b6 c0 33 0c 85 ?? ?? ?? ?? 46 83 ea 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MyloBot_A_2147896852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MyloBot.A!MTB"
        threat_id = "2147896852"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MyloBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 32 33 f0 81 e6 ?? ?? ?? ?? c1 e8 ?? 33 04 b5 ?? ?? ?? ?? 42 49}  //weight: 2, accuracy: Low
        $x_2_2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)" ascii //weight: 2
        $x_2_3 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 2
        $x_2_4 = "HTTP/1.0 200" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

