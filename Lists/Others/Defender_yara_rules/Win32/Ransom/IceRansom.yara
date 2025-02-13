rule Ransom_Win32_IceRansom_YAA_2147852983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/IceRansom.YAA!MTB"
        threat_id = "2147852983"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "IceRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ICE_Recovey.txt" wide //weight: 1
        $x_1_2 = "+++ BLACK ICE +++" ascii //weight: 1
        $x_1_3 = "ICE\" extension" ascii //weight: 1
        $x_1_4 = "FILES ARE STOLEN AND ENCRYPTED" ascii //weight: 1
        $x_1_5 = "restore your files" ascii //weight: 1
        $x_1_6 = "vssadmin.exe delete shadows /all /quiet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

