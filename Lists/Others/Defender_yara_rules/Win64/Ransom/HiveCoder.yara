rule Ransom_Win64_HiveCoder_CC_2147834333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/HiveCoder.CC!MTB"
        threat_id = "2147834333"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "HiveCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "!error: no flag -u <login>:<password> provided" ascii //weight: 2
        $x_1_2 = "VirtualProtect failed with code 0x%x" ascii //weight: 1
        $x_1_3 = ".key" ascii //weight: 1
        $x_1_4 = "BCryptGenRandom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

