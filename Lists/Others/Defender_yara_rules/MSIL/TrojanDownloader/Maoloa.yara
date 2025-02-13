rule TrojanDownloader_MSIL_Maoloa_A_2147844634_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Maoloa.A!MTB"
        threat_id = "2147844634"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Maoloa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 8e 69 5d 91 07 09 91 61 d2 6f 08 00 16 0d 2b ?? 06 09 08 09}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 0a 25 02 6f ?? 00 00 0a 0a 6f ?? 00 00 0a 06 0b de}  //weight: 2, accuracy: Low
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
        $x_1_5 = "GetMethod" ascii //weight: 1
        $x_1_6 = "CreateDelegate" ascii //weight: 1
        $x_1_7 = "DynamicInvoke" ascii //weight: 1
        $x_1_8 = "ToString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

