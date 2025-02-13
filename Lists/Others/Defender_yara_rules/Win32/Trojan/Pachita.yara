rule Trojan_Win32_Pachita_A_2147624927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pachita.gen!A"
        threat_id = "2147624927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pachita"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {42 74 6e 69 6e 66 ?? ?? ?? ?? ?? (49 6e 66 65 63|43 6c 6f 6e)}  //weight: 5, accuracy: Low
        $x_2_2 = {46 72 6d 5a 69 74 61 00}  //weight: 2, accuracy: High
        $x_2_3 = "-C000-Zita" ascii //weight: 2
        $x_1_4 = "Execution Options\\ctfmon.exe\\Debugger" wide //weight: 1
        $x_1_5 = "HKEY_CLASSES_ROOT\\exefile\\NeverShowExt" wide //weight: 1
        $x_1_6 = "CurrentVersion\\Explorer\\Advanced\\Folder" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

