rule Trojan_Win32_Warzone_MA_2147846648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Warzone.MA!MTB"
        threat_id = "2147846648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Warzone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8d 4f 2c 48 03 c8 8b 51 f8 4d 2b d6 44 8b 01 48 03 d6 44 8b 49 fc 4c 03 c5 4d 85 c9 74 ?? 41 8a 00 4d 03 c6 88 02 49 03 d6 4d 2b ce 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Warzone_MBJB_2147891787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Warzone.MBJB!MTB"
        threat_id = "2147891787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Warzone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 0f 8b c1 6a 64 99 5f f7 ff 8a 44 14 18 30 04 29 41 81 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

