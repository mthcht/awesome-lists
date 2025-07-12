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
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\cleanup.bat" wide //weight: 1
        $x_1_2 = "schtasks /create /tn" ascii //weight: 1
        $x_3_3 = "Ooops, your files got fucked by D.U.R.R Ransom" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

