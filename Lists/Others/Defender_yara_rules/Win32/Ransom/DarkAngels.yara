rule Ransom_Win32_DarkAngels_MA_2147901618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DarkAngels.MA!MTB"
        threat_id = "2147901618"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkAngels"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "D A R K" ascii //weight: 3
        $x_3_2 = "A N G E L S" ascii //weight: 3
        $x_3_3 = "your network infrastructure has been compromised" ascii //weight: 3
        $x_3_4 = "backup Don't rename crypted files and create note" ascii //weight: 3
        $x_3_5 = "and we will share all the leaked data for free" ascii //weight: 3
        $x_3_6 = "Decryption key will be deleted permanently and recovery will be impossible" ascii //weight: 3
        $x_1_7 = "How To Restore Your Files.txt" wide //weight: 1
        $x_1_8 = "ROOT\\cimv2" wide //weight: 1
        $x_1_9 = "select * from Win32_ShadowCopy" wide //weight: 1
        $x_1_10 = "files are encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_3_*) and 4 of ($x_1_*))) or
            ((5 of ($x_3_*) and 1 of ($x_1_*))) or
            ((6 of ($x_3_*))) or
            (all of ($x*))
        )
}

