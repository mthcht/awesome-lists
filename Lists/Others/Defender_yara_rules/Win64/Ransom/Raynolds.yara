rule Ransom_Win64_Raynolds_YBG_2147962787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Raynolds.YBG!MTB"
        threat_id = "2147962787"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Raynolds"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sophos UI.exe" wide //weight: 1
        $x_1_2 = "MsMpEng.exe" wide //weight: 1
        $x_1_3 = "WriteDriver" ascii //weight: 1
        $x_1_4 = "files have been encrypted" ascii //weight: 1
        $x_1_5 = "Tor Browser" ascii //weight: 1
        $x_1_6 = "RestoreYourFiles" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

