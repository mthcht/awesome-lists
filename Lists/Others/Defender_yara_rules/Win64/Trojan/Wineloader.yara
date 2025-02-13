rule Trojan_Win64_Wineloader_A_2147908936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Wineloader.A"
        threat_id = "2147908936"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Wineloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 00 01 00 00 99 f7 f9 8b 44 24 ?? 48 63 d2 ?? ?? ?? ?? ?? ?? ?? 0f b6 0c 11 01 c8 88 c1 48 8b 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 44 24 ?? 0f b6 00 3d ff 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 83 ec 08 ?? ?? ?? ?? ?? ?? ?? 48 c7 c2 28 80 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 05 30 8e 00 00 48 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 48 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

