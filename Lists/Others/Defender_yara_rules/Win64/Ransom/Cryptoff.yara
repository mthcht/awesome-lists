rule Ransom_Win64_Cryptoff_CCJT_2147929811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Cryptoff.CCJT!MTB"
        threat_id = "2147929811"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Cryptoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8b c8 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 4c 8d 35 ?? ?? 01 00 4c 89 75 c7 4c 8d 25 ?? ?? 01 00 4c 89 65 cf 0f 28 45 c7 66 0f 7f 45 c7 41 b1 01 [0-3] 48 8d 55 c7 e8 ?? ?? ?? ?? c7 45 67 50 00 bb 01 48 8d 45 67 48 89 45 c7 48 8d 45 6b 48 89 45 cf 0f 28 45 c7 66 0f 7f 45 c7 48 8d 55 c7 48 8d 4d e7 e8}  //weight: 5, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "Sending request for hidden service descriptor..." ascii //weight: 1
        $x_1_4 = "Hidden service descriptor received..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

