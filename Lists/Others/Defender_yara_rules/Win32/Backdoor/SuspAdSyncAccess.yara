rule Backdoor_Win32_SuspAdSyncAccess_A_2147970395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/SuspAdSyncAccess.A!hva"
        threat_id = "2147970395"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspAdSyncAccess"
        severity = "Critical"
        info = "hva: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\esentutl.exe" wide //weight: 10
        $x_10_2 = "/y " wide //weight: 10
        $x_10_3 = "ADSync.mdf" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

