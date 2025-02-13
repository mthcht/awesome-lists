rule Worm_Win32_Bruhorn_A_2147598081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bruhorn.A"
        threat_id = "2147598081"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bruhorn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SOFTWARE\\Microsoft\\Security Center" wide //weight: 2
        $x_2_2 = "AntiVirusDisableNotify" wide //weight: 2
        $x_1_3 = "FirewallDisableNotify" wide //weight: 1
        $x_2_4 = "HIJACKTHIS" wide //weight: 2
        $x_1_5 = "AVIRA" wide //weight: 1
        $x_2_6 = "\\New Folder.exe" wide //weight: 2
        $x_2_7 = "\\Folder.htt" wide //weight: 2
        $x_2_8 = "PersistMoniker=file:" wide //weight: 2
        $x_1_9 = "batfile\\shell\\open\\command" wide //weight: 1
        $x_1_10 = "New Folder." wide //weight: 1
        $x_1_11 = "document.writeln(" wide //weight: 1
        $x_1_12 = "ScreenSaverIsSecure" wide //weight: 1
        $n_18_13 = "PC Media Antivirus Log File" wide //weight: -18
        $n_18_14 = "PC Media Antivirus Log File" ascii //weight: -18
        $n_18_15 = "pcmav-log" ascii //weight: -18
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Bruhorn_B_2147598083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bruhorn.B"
        threat_id = "2147598083"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bruhorn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "LatihanVB\\Virus" wide //weight: 8
        $x_1_2 = "\\CurrentVersion\\Explorer\\Advanced\\" wide //weight: 1
        $x_1_3 = "ShowSuperHidden" wide //weight: 1
        $x_1_4 = "ExploreWClass" wide //weight: 1
        $x_1_5 = "Folder Option" wide //weight: 1
        $x_1_6 = "DETEC\\x00" wide //weight: 1
        $x_1_7 = "\\Folder.htt" wide //weight: 1
        $x_1_8 = "Users\\Start Menu\\Programs\\Startup" wide //weight: 1
        $x_1_9 = "NT\\CurrentVersion\\AeDebug" wide //weight: 1
        $x_1_10 = "lnkfile\\shell\\open\\command" wide //weight: 1
        $x_1_11 = "piffile\\shell\\open\\command" wide //weight: 1
        $x_2_12 = "<object id=FileList border=0 tabindex=1" wide //weight: 2
        $x_2_13 = "PersistMoniker=file://" wide //weight: 2
        $x_2_14 = "document.writeln(" wide //weight: 2
        $x_1_15 = "Line1 = Your computer has been infected" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_8_*) and 6 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

