rule TrojanProxy_Win32_Thrap_A_2147601393_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Thrap.gen!A"
        threat_id = "2147601393"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Thrap"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {75 02 eb 38 c7 45 fc 00 00 00 00 eb 09 8b 45 fc 83 c0 01 89 45 fc 8b 4d 08 51 e8 ?? ?? 00 00 83 c4 04 39 45 fc 7d 15 8b 55 08 03 55 fc 8a 02 32 45 0c 8b 4d 08 03 4d fc 88 01 eb d1}  //weight: 10, accuracy: Low
        $x_6_2 = {83 bd ec fd ff ff 0a 74 42 81 bd ec fd ff ff ac 00 00 00 75 12 83 bd e8 fd ff ff 0f 7e 09 83 bd e8 fd ff ff 20 7c 24}  //weight: 6, accuracy: High
        $x_3_3 = "~fsock1/god.php" ascii //weight: 3
        $x_3_4 = "NlMediaCenter" ascii //weight: 3
        $x_3_5 = "%s?pip=%s&port=%d" ascii //weight: 3
        $x_1_6 = "SYSTEM\\\\CurrentControlSet\\\\Services\\\\SharedAccess\\\\Parameters\\\\FirewallPolicy\\\\StandardProfile\\\\AuthorizedApplications\\\\List" ascii //weight: 1
        $x_1_7 = "G%y%m%d%H%M%S.%. %p %E %U %C:%c %R:%r %O %I %h %T" ascii //weight: 1
        $x_1_8 = "Documentation and sources: http://www.security.nnov.ru/soft/3proxy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*))) or
            (all of ($x*))
        )
}

