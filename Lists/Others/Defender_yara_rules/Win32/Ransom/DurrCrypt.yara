rule Ransom_Win32_DurrCrypt_PA_2147946159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DurrCrypt.PA!MTB"
        threat_id = "2147946159"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DurrCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RansomwareUIClass" ascii //weight: 1
        $x_1_2 = "C:\\ProgramData\\Durr.lock" ascii //weight: 1
        $x_1_3 = "schtasks /create /tn" ascii //weight: 1
        $x_4_4 = "D.U.R.R Ransom" wide //weight: 4
        $x_4_5 = "Your important files have been encrypted using military grade algorithms" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

