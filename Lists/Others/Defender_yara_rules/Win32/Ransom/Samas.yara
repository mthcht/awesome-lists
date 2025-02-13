rule Ransom_Win32_Samas_2147727291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Samas"
        threat_id = "2147727291"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Samas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iplogger.com/" wide //weight: 1
        $x_1_2 = "DeleteORAutoRun.exe" wide //weight: 1
        $x_1_3 = "Loader By TetrissPlay" wide //weight: 1
        $x_1_4 = "SELECT * FROM Win32_OperatingSystem" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

