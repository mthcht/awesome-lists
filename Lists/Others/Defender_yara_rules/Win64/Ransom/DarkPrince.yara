rule Ransom_Win64_DarkPrince_YBG_2147962438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/DarkPrince.YBG!MTB"
        threat_id = "2147962438"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "DarkPrince"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks /Delete /TN \"WindowsLock\" /F" wide //weight: 1
        $x_1_2 = "Destroying MBR" wide //weight: 1
        $x_1_3 = "captured by the Dark Prince" wide //weight: 1
        $x_1_4 = "Windows is locked" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

