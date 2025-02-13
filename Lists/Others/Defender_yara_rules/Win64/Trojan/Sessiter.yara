rule Trojan_Win64_Sessiter_A_2147825485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sessiter.A!dha"
        threat_id = "2147825485"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sessiter"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 cd ff 00 00 66 89 8c 04 ?? ?? ?? ?? b8 02 00 00 00 48 6b c0 01 b9 cc ff 00 00 66 89 8c 04 ?? ?? ?? ?? b8 02 00 00 00 48 6b c0 02 b9 93 ff 00 00 66 89 8c 04 ?? ?? ?? ?? b8 02 00 00 00 48 6b c0 03 b9 9a ff 00 00 66 89 8c 04 ?? ?? ?? ?? b8 02 00 00 00 48 6b c0 04 b9 91 ff 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e0 14 8b 0c 24 c1 e9 0c 0b c1 89 04 24 48 8b 44 24 ?? 0f be 00 83 f8 61 7c ?? 48 8b 44 24 ?? 0f be 00 83 e8 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sessiter_B_2147825486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sessiter.B!dha"
        threat_id = "2147825486"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sessiter"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {48 81 ec 08 00 00 00 66 b9 ?? ?? e8 00 00 00 00 66 89 4c 24 08 48 81 ec a8 01 00 00 ba 08 00 00 00 b9 01 00 00 00 e8}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

