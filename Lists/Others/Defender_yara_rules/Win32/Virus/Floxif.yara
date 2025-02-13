rule Virus_Win32_Floxif_RPX_2147888900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Floxif.RPX!MTB"
        threat_id = "2147888900"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Floxif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 51 02 33 c2 8b 4d 08 03 4d fc 88 01 8b 55 08 03 55 fc 33 c0 8a 02 f7 d0 8b 4d 08}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec b8 01 00 00 00 85 c0 74 0d 68 60 ea 00 00 ff 15 ?? ?? ?? ?? eb ea 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Floxif_RDA_2147891274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Floxif.RDA!MTB"
        threat_id = "2147891274"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Floxif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 85 78 ff ff ff 33 d2 f7 75 94 8b 85 64 fe ff ff 0f be 14 10 33 ca 8b 45 90}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Floxif_EC_2147909550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Floxif.EC!MTB"
        threat_id = "2147909550"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Floxif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8d 42 04 53 8b c8 8a 5a 02 84 db 74 02 30 19 8a 19 f6 d3 84 db 88 19 74 03 41 eb ea}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

