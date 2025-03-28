rule Trojan_Win64_RALord_SACR_2147937160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RALord.SACR!MTB"
        threat_id = "2147937160"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RALord"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RALord ransomware " ascii //weight: 2
        $x_1_2 = "ThreadPoolBuildErrorkindREADME-.txt" ascii //weight: 1
        $x_1_3 = "you can recover the files by contact us and pay the ransom " ascii //weight: 1
        $x_1_4 = "you see this Readme its mean you under controll by RLord ransomware" ascii //weight: 1
        $x_1_5 = "the data has been stolen and everything done " ascii //weight: 1
        $x_1_6 = "please do not touch the files becouse we can't decrypt it if you touch it" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

