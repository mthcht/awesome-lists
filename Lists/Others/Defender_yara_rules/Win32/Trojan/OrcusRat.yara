rule Trojan_Win32_OrcusRat_MBXQ_2147918550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OrcusRat.MBXQ!MTB"
        threat_id = "2147918550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OrcusRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {89 11 a4 02 42 00 00 08 31 08 a1 ?? ?? ?? 00 08 00 c8 eb 56 00}  //weight: 3, accuracy: Low
        $x_2_2 = {64 1b 40 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 03 00 00 00 e9 00 00 00 d0 15 40 00 d8 14 40 00 f0 13 40 00 78 00 00 00 80}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OrcusRat_A_2147964576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OrcusRat.A!AMTB"
        threat_id = "2147964576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OrcusRat"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Wave Key Loader" ascii //weight: 1
        $x_1_2 = "Have you disabled Tamper Protection" ascii //weight: 1
        $x_1_3 = "Generating fake key hash" ascii //weight: 1
        $x_1_4 = "Initializing bypass sequence" ascii //weight: 1
        $x_1_5 = "discord.gg/water" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

