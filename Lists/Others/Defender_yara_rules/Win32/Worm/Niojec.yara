rule Worm_Win32_Niojec_2147605121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Niojec"
        threat_id = "2147605121"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Niojec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\secpol.exe" wide //weight: 2
        $x_2_2 = {43 00 6e 00 39 00 31 00 31 00 00 00}  //weight: 2, accuracy: High
        $x_1_3 = "SeBackupPrivilege" wide //weight: 1
        $x_1_4 = "SeRestorePrivilege" wide //weight: 1
        $x_10_5 = {c7 45 fc 09 00 00 00 e8 ?? ?? ?? ?? c7 45 fc 0a 00 00 00 68 88 13 00 00 e8 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? c7 45 fc 0b 00 00 00 ff 15 ?? ?? ?? ?? c7 45 fc 0c 00 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Niojec_B_2147617695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Niojec.B"
        threat_id = "2147617695"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Niojec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cn914\\msiexec" ascii //weight: 1
        $x_1_2 = "SeBackupPrivilege" ascii //weight: 1
        $x_1_3 = "SeRestorePrivilege" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\PlayOnlineUS\\InstallFolder" ascii //weight: 1
        $x_1_5 = "DeleteMe.bat" ascii //weight: 1
        $x_10_6 = {ba 60 78 40 00 e8 77 34 00 00 6a 00 8b dc e8 c1 2d 00 00 ba 54 78 40 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

