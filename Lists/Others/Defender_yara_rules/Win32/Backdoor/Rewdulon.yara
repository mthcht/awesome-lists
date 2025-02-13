rule Backdoor_Win32_Rewdulon_A_2147637638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rewdulon.A"
        threat_id = "2147637638"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rewdulon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {80 0c 00 6c ?? ff e4 f4 ff fe 5d 20 00 6c ?? ff e4 04 ?? ff f5 00 00 00 00 fc 75 6c ?? ff e4 fd 3d 6c ?? ff 43 ?? ff ff 2f}  //weight: 3, accuracy: Low
        $x_1_2 = "GETKL" wide //weight: 1
        $x_1_3 = "241 Change Drive OK" wide //weight: 1
        $x_1_4 = "DCLICK" wide //weight: 1
        $x_1_5 = "(REOMOVABLE)" wide //weight: 1
        $x_1_6 = "SOFTWARE\\SystemControler" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Rewdulon_B_2147637639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rewdulon.B"
        threat_id = "2147637639"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rewdulon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {80 10 00 04 70 ff 34 6c 70 ff 80 0c 00 5e ?? ?? ?? 00 71 6c ff 3c 6c 70 ff 6c 10 00 fc 58 6c 6c ff 71 78 ff 2f 70 ff 6c 78 ff fc 52 1c 30 00 14 6c 74 ff 0a ?? ?? ?? 00 3c 14 f5}  //weight: 3, accuracy: Low
        $x_1_2 = "SOFTWARE\\SystemControler" wide //weight: 1
        $x_1_3 = "\\Remote Startup\\" wide //weight: 1
        $x_1_4 = "OutlookSMTP.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

