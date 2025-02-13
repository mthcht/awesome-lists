rule Trojan_Win64_CymRun_RDA_2147903486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CymRun.RDA!MTB"
        threat_id = "2147903486"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CymRun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Finished encrypting all files (%d out of %d), getting evidence" ascii //weight: 1
        $x_1_2 = "Overall files to encrypt %d" ascii //weight: 1
        $x_1_3 = "Missing encryption_path argument" ascii //weight: 1
        $x_1_4 = "Using default cnc url" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

