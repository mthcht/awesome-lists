rule Trojan_Win32_ModifySystemRegistry_A_2147920800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ModifySystemRegistry.A"
        threat_id = "2147920800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ModifySystemRegistry"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {72 00 65 00 67 00 [0-8] 20 00 61 00 64 00 64 00 20 00}  //weight: 6, accuracy: Low
        $x_1_2 = "hkcu\\software\\microsoft\\windows\\currentversion\\policies\\activedesktop /v nochangingwallpaper" wide //weight: 1
        $x_1_3 = {68 00 6b 00 63 00 75 00 5c 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 20 00 70 00 61 00 6e 00 65 00 6c 00 5c 00 64 00 65 00 73 00 6b 00 74 00 6f 00 70 00 [0-2] 20 00 2f 00 76 00 20 00 77 00 61 00 6c 00 6c 00 70 00 61 00 70 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_4 = "hklm\\software\\microsoft\\windows\\currentversion\\policies\\system /v wallpaper" wide //weight: 1
        $x_1_5 = "hklm\\software\\microsoft\\windows\\currentversion\\policies\\system /v wallpaperstyle" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

