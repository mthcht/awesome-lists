rule Worm_Win32_Swimnag_A_2147609965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Swimnag.gen!A"
        threat_id = "2147609965"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Swimnag"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 00 61 00 73 00 70 00 65 00 72 00 73 00 6b 00 79 00 00 00 54 00 68 00 65 00 20 00 41 00 76 00 65 00 6e 00 67 00 65 00 72 00 00 00 52 00 6f 00 6f 00 74 00 6b 00 69 00 74 00 52 00 65 00 76 00 65 00 61 00 6c 00 65 00 72 00}  //weight: 1, accuracy: High
        $x_1_2 = "Inject in" wide //weight: 1
        $x_1_3 = "StartShell" wide //weight: 1
        $x_1_4 = "pd[wmid]=" wide //weight: 1
        $x_1_5 = "pd[msg]=" wide //weight: 1
        $x_1_6 = "%04i-%02i-%02i %02i:%02i:%02i:%03i" wide //weight: 1
        $x_1_7 = "if exist \"" ascii //weight: 1
        $x_1_8 = "WriteProcessMemory" ascii //weight: 1
        $x_1_9 = "CreateRemoteThread" ascii //weight: 1
        $x_1_10 = {8b 45 cc 8b 4d e4 ff 34 81 ff 15 ?? ?? ?? 00 85 c0 75 0b c7 45 e8 01 00 00 00 83 65 bc 00 eb c6}  //weight: 1, accuracy: Low
        $x_1_11 = {73 64 65 73 63 00 00 00 73 64 69 73 70 6c 61 79 00 00 00 00 73 65 72 76 64 6c 6c 64 69 73 70 6c 61 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Worm_Win32_Swimnag_A_2147620488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Swimnag.gen!A"
        threat_id = "2147620488"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Swimnag"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {eb 26 8b 45 f0 89 45 ec 81 7d ec ?? ?? ?? ?? 73 07 c7 45 ec ?? ?? ?? ?? 81 7d ec ?? ?? ?? ?? 76 07}  //weight: 5, accuracy: Low
        $x_5_2 = "udtConfigTimer" wide //weight: 5
        $x_5_3 = "udtUnLockEventR" wide //weight: 5
        $x_5_4 = "udtUnLockEventQ" wide //weight: 5
        $x_1_5 = "self_version" wide //weight: 1
        $x_1_6 = "config_version" wide //weight: 1
        $x_1_7 = "last_config_update" wide //weight: 1
        $x_1_8 = "%04i-%02i-%02i %02i:%02i:%02i:%03i" wide //weight: 1
        $x_1_9 = "config_update_period" wide //weight: 1
        $x_5_10 = {6c 00 74 00 69 00 67 00 76 00 74 00 69 00 6f 00 64 00 6f 00 70 00 64 00 73 00 72 00 6c 00 72 00 00 00}  //weight: 5, accuracy: High
        $x_5_11 = {6c 00 74 00 69 00 67 00 76 00 74 00 69 00 6f 00 64 00 6f 00 70 00 64 00 73 00 72 00 6c 00 71 00 00 00}  //weight: 5, accuracy: High
        $x_1_12 = "after_startup_delay" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

