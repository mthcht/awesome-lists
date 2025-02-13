rule Trojan_Win64_EncSivisLoader_A_2147807781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EncSivisLoader.A"
        threat_id = "2147807781"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EncSivisLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fileSYS" ascii //weight: 1
        $x_1_2 = "filePayload" ascii //weight: 1
        $x_1_3 = "GZipStream" ascii //weight: 1
        $x_1_4 = "get_CurrentDomain" ascii //weight: 1
        $x_1_5 = "OnResolveAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

