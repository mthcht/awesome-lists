rule Trojan_Win64_Redlinestealer_PGA_2147939516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redlinestealer.PGA!MTB"
        threat_id = "2147939516"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redlinestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "185.81.68.147/bin/bot64.bin" ascii //weight: 1
        $x_1_2 = "CurrentVersion\\Explorer\\StartupApproved\\Run" ascii //weight: 1
        $x_1_3 = "bitcoincash" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

