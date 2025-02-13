rule Trojan_Win32_DarkWatchman_EZ_2147827961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkWatchman.EZ!MTB"
        threat_id = "2147827961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkWatchman"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ":: Clipboard" wide //weight: 10
        $x_1_2 = "j343a7e4d" ascii //weight: 1
        $x_2_3 = "d3b7175b9" ascii //weight: 2
        $x_1_4 = "a76076210" ascii //weight: 1
        $x_2_5 = "g1e32aaa4" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

