rule HackTool_Win64_ITuneByPass_MBWK_2147929492_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/ITuneByPass.MBWK!MTB"
        threat_id = "2147929492"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "ITuneByPass"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {67 69 74 68 75 62 2e 63 6f 6d 2f [0-47] 2f 74 6f 6b 65 6e 73 6d 69 74 68 2f 63 6d 64}  //weight: 2, accuracy: Low
        $x_1_2 = {67 69 74 68 75 62 2e 63 6f 6d 2f [0-47] 2f 6d 6f 75 73 65 74 72 61 70}  //weight: 1, accuracy: Low
        $x_1_3 = "intune-bypassresponse_type_active" ascii //weight: 1
        $x_1_4 = {2f 75 73 72 2f 6c 6f 63 61 6c 2f 67 6f 2f 73 72 63 2f 72 75 6e 74 69 6d 65 2f [0-47] 2e 67 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

