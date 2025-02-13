rule TrojanDownloader_Win32_Raemnk_A_2147658502_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Raemnk.A"
        threat_id = "2147658502"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Raemnk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ":\\GERA\\bin\\" wide //weight: 1
        $x_1_2 = "\\Desktop\\ENVIO\\bin\\" wide //weight: 1
        $x_10_3 = {6c 54 ff 2a 23 4c ff 08 08 00 06 ?? 00 24 ?? 00 0d 44 00 ?? 00 6b 4a ff f4 ff c6 32 08 00 58 ff 50 ff 54 ff 4c ff 35 5c ff 1c af 00 00 53 3a 6c ff ?? 00 4e 5c ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Raemnk_A_2147658502_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Raemnk.A"
        threat_id = "2147658502"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Raemnk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 45 fc 01 00 00 00 c7 45 fc 02 00 00 00 6a ff e8 ?? ?? ?? ?? c7 45 fc 03 00 00 00 c7 45 a0 ?? ?? ?? ?? c7 45 98 08 00 00 00 8d 55 98}  //weight: 10, accuracy: Low
        $x_1_2 = {66 8b c8 66 2b 4d ?? 0f 80 ?? ?? 00 00 66 03 ce 0f 80 ?? ?? 00 00 0f bf c9 3b cb 7d ?? 6a 1e 59 66 2b c1 b9 ff 00 00 00 0f 80 ?? ?? 00 00 66 03 c6 0f 80 ?? ?? 00 00 66 2b 4d 00 0f 80 ?? ?? 00 00 66 03 ce 0f 80 ?? ?? 00 00 66 03 c1 0f 80 ?? ?? 00 00 0f bf c8}  //weight: 1, accuracy: Low
        $x_1_3 = {66 8b c8 66 2b 4d ?? 0f 80 ?? ?? 00 00 66 03 ce 0f 80 ?? ?? 00 00 0f bf c9 3b cb 7d ?? b9 ff 00 00 00 6a 1e 66 8b d1 59 66 2b 55 00 0f 80 ?? ?? 00 00 66 03 d6 0f 80 ?? ?? 00 00 66 2b c1 0f 80 ?? ?? 00 00 66 03 c6 0f 80 ?? ?? 00 00 66 03 d0 0f 80 ?? ?? 00 00 0f bf ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

