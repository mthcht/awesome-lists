rule Ransom_Win32_Fonix_MB_2147766367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Fonix.MB!MTB"
        threat_id = "2147766367"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Fonix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\Phoenix\\Downloads\\cryptopp800" ascii //weight: 1
        $x_1_2 = "Lock already taken" ascii //weight: 1
        $x_1_3 = "Policies\\Explorer   /v NoRun  /t REG_DWORD /d 0 /f" ascii //weight: 1
        $x_1_4 = "\"status\":\"Complete\"}" ascii //weight: 1
        $x_1_5 = "End - GoodLuck" ascii //weight: 1
        $x_1_6 = "Encryption Completed" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

