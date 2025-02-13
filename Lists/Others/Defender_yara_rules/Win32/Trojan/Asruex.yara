rule Trojan_Win32_Asruex_A_2147708363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Asruex.A!dha"
        threat_id = "2147708363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Asruex"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 1c 8d 4c 24 30 56 8a 1c 30 80 c3 ?? e8 ?? ?? ?? ?? 46 8b 00 88 1c 28 3b f7 72 e2}  //weight: 1, accuracy: Low
        $x_1_2 = {85 c0 74 06 c6 46 6c 20 eb 04 c6 46 6c 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Asruex_A_2147742113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Asruex.A"
        threat_id = "2147742113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Asruex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 44 00 00 00 8d 44 24 20 88 18 40 83 e9 01 75 f8 c7 44 24 20 44 00 00 00 b9 10 00 00 00 8d 44 24 10 8d 49 00 88 18 40 83 e9 01 75 f8 8b 0d 28 54 4d 00 8b 11 52}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

