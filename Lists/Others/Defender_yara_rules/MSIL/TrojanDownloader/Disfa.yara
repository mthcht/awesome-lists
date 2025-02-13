rule TrojanDownloader_MSIL_Disfa_NIT_2147921881_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Disfa.NIT!MTB"
        threat_id = "2147921881"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disfa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7}  //weight: 2, accuracy: High
        $x_1_2 = "WriteAllBytes" ascii //weight: 1
        $x_1_3 = "BlackDropperNET" ascii //weight: 1
        $x_1_4 = "HttpContent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

