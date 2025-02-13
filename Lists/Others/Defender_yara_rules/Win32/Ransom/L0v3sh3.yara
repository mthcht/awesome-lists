rule Ransom_Win32_L0v3sh3_AA_2147844875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/L0v3sh3.AA!MTB"
        threat_id = "2147844875"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "L0v3sh3"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".L0v3sh3" ascii //weight: 1
        $x_1_2 = ".payme100usdz" ascii //weight: 1
        $x_1_3 = "PayMe" ascii //weight: 1
        $x_1_4 = "encryptedSessionKey" ascii //weight: 1
        $x_1_5 = "encryptedFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

