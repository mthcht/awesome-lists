rule Backdoor_Win64_Bazdor_B_2147786764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bazdor.B!MTB"
        threat_id = "2147786764"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazdor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 83 ec 20 48 89 6c 24 18 48 8d 6c 24 18 65 48 8b 0c 25 28 00 00 00 bb 00 00 00 00 48 83 f9 00 74 07 48 8b 99 00 00 00 00 48 83 fb 00 74 0b 48 8b 5b 30 48 89 5c 24 10 eb 2d}  //weight: 10, accuracy: High
        $x_3_2 = "_cgo_dummy_export" ascii //weight: 3
        $x_3_3 = "aexjnnjyyaqdoa" ascii //weight: 3
        $x_3_4 = "cdacoeunenemg" ascii //weight: 3
        $x_3_5 = "cbdjvxrpoivxwfrvajh." ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

