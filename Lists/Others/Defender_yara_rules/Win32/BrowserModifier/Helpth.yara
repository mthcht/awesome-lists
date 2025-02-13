rule BrowserModifier_Win32_Helpth_123283_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Helpth"
        threat_id = "123283"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Helpth"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Thunder5Helper" ascii //weight: 3
        $x_3_2 = "ThunderBHONew.dll" wide //weight: 3
        $x_2_3 = "http://www.baidu.com/s?wd=" ascii //weight: 2
        $x_1_4 = "union.2008djf.cn/search/n/" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\Browser Helper Objects\\" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\360" ascii //weight: 1
        $x_1_7 = "http://click.p4p.cn.yahoo.com/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Helpth_123283_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Helpth"
        threat_id = "123283"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Helpth"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "103"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {68 74 74 70 [0-3] 3a 2f 2f 78 [0-3] 75 6c 65 69 [0-3] 38 38 38 2e [0-3] 77 39 39 2e [0-3] 6d 79 64 6e [0-3] 6e 73 2e 63 [0-3] 6e 2f 64 61 [0-3] 74 61 [0-9] 65 [0-3] 78 65}  //weight: 100, accuracy: Low
        $x_1_2 = "thunder5_app_mutex" ascii //weight: 1
        $x_1_3 = "Thunder Exit Shell" ascii //weight: 1
        $x_1_4 = "Thunder_Special_Urls" ascii //weight: 1
        $x_1_5 = "thunder5_shell_mutex" ascii //weight: 1
        $x_1_6 = {00 74 68 75 6e 64 65 72 35 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = "Thunder_Files_To" ascii //weight: 1
        $x_1_8 = {53 68 65 6c 6c 5f 43 61 6c 6c 00 00 50 72 6f 67 72 61 6d 5c 55 70 64 61 74 65 53 68 65 6c 6c 2e 64 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

