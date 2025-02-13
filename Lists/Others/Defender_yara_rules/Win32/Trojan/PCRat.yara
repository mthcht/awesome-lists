rule Trojan_Win32_PCRat_RDA_2147839480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PCRat.RDA!MTB"
        threat_id = "2147839480"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 89 44 24 12 8b 47 0c 6a 10 8b 08 8d 44 24 14 50 8b 11 8b 4e 08 51 89 54 24 20 ff 15 a0 20 40 00 83 f8 ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PCRat_RPZ_2147845787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PCRat.RPZ!MTB"
        threat_id = "2147845787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 8d 4c 24 14 68 00 10 00 00 51 50 ff 15 ?? ?? ?? ?? 8b e8 85 ed 7e 32 8b 53 04 8b cd 8d 74 24 10 8d 7c 1a 10 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 8b 4b 04 03 cd 8b c1 89 4b 04 3d 5c dd 04 00 73 08 8b 43 08 83 f8 ff 75 b5}  //weight: 1, accuracy: Low
        $x_1_2 = "112.213.117.42:1150" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

