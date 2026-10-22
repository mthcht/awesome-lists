rule Trojan_Win32_RunDialogLaunch_C_2147980775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RunDialogLaunch.C"
        threat_id = "2147980775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RunDialogLaunch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "rundll32.exe" wide //weight: 1
        $x_1_2 = {73 00 68 00 65 00 6c 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 [0-8] 2c 00 23 00 36 00 31 00 [0-8] 32 00 32 00 34 00 30 00 35 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

