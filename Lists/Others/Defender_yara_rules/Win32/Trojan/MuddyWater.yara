rule Trojan_Win32_MuddyWater_MZV_2147964483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MuddyWater.MZV!MTB"
        threat_id = "2147964483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MuddyWater"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http" wide //weight: 2
        $x_2_2 = "hidden" wide //weight: 2
        $x_6_3 = "currentversion\\run" wide //weight: 6
        $x_10_4 = ".env.get(username)" wide //weight: 10
        $x_40_5 = "eblink.kyun.li" wide //weight: 40
        $x_60_6 = "imh0dha6ly9lymxpbmsua3l1bi5sasi" wide //weight: 60
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_40_*) and 1 of ($x_10_*) and 1 of ($x_6_*) and 2 of ($x_2_*))) or
            ((1 of ($x_60_*))) or
            (all of ($x*))
        )
}

