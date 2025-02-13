rule Trojan_Win32_Silentbanker_B_2147603040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Silentbanker.B"
        threat_id = "2147603040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Silentbanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 83 ec 54 53 56 57 6a 06 59 be ?? ?? ?? ?? 8d 7d e4 f3 a5 66 a5 a4 6a 06 59 be ?? ?? ?? ?? 8d 7d c8 f3 a5 8b 5d 08 66 a5 a4 6a 06 59 be ?? ?? ?? ?? 8d 7d ac f3 a5 66 a5 8d 45 e4 53 50 a4 e8 ?? ?? ff ff 85 c0 59 59 74 14 8d 4d e4 2b c1 83 c0 ?? 99 6a 1a 59 f7 f9 8a 44 15 e4 eb 4a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Silentbanker_B_2147603041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Silentbanker.B"
        threat_id = "2147603041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Silentbanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 54 24 04 8d 0c 40 8d 0c 88 c1 e1 04 03 c8 c1 e1 08 2b c8 8d 84 88 c3 9e 26 00 8b c8 c1 e9 10 0f af ca c1 e9 10 74 dc a3 ?? ?? ?? ?? 8b c1 c2 04 00 0f 00 a1 ?? ?? ?? ?? 85 c0 75 06 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {b9 fb 03 00 00 b8 20 20 20 20 bf ?? ?? ?? ?? f3 ab 66 ab bf ee 0f 00 00 c7 44 24 10 00 00 00 00 8b 44 24 10 8b 74 24 1c d1 e8 f6 c4 01 89 44 24 10 75 1b}  //weight: 10, accuracy: Low
        $x_10_3 = "%s%x%x.dat" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

