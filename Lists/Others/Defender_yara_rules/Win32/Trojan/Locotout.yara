rule Trojan_Win32_Locotout_A_2147654285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Locotout.gen!A"
        threat_id = "2147654285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Locotout"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {74 05 50 ff d7 b3 01 56 ff d7 84 db 5f 74 2b e8}  //weight: 6, accuracy: High
        $x_6_2 = "cmd /c net start %s" ascii //weight: 6
        $x_1_3 = "link.php?data" ascii //weight: 1
        $x_1_4 = "?action=logout" ascii //weight: 1
        $x_1_5 = {3c 64 69 61 70 3e 00}  //weight: 1, accuracy: High
        $x_1_6 = {64 76 3d 00 76 72 3d 00 6d 65 3d 00}  //weight: 1, accuracy: High
        $x_1_7 = "att%dcontent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            ((2 of ($x_6_*))) or
            (all of ($x*))
        )
}

