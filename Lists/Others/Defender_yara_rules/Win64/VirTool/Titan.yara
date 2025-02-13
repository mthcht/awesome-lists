rule VirTool_Win64_Titan_A_2147910516_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Titan.A"
        threat_id = "2147910516"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Titan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "object KvgkfssForm: TKvgkfssForm" ascii //weight: 1
        $x_1_2 = "CryptDestroyKey" ascii //weight: 1
        $x_1_3 = "object PiybqbaForm: TPiybqbaForm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

