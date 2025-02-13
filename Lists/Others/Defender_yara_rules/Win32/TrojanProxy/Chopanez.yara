rule TrojanProxy_Win32_Chopanez_A_2147604980_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Chopanez.gen!A"
        threat_id = "2147604980"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Chopanez"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {74 65 55 8b 2d ?? ?? 40 00 8b ff 8d 54 24 14 52 68 00 28 00 00 8d 44 24 30 50 53 c7 44 24 24 00 28 00 00 ff 15 ?? ?? 40 00 85 c0 74 34 8b 44 24 14 85 c0 74 31}  //weight: 5, accuracy: Low
        $x_1_2 = "G%y%m%d%H%M%S.%. %p %E %U %C:%c %R:%r %O %I %h %T" ascii //weight: 1
        $x_1_3 = "Accepting connections [%u/%u]" ascii //weight: 1
        $x_1_4 = ":TCP:*:Enabled:Microsoft standard protector" ascii //weight: 1
        $x_1_5 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\GloballyOpenPorts\\List" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

