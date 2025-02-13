rule Backdoor_MSIL_Evilnum_SP_2147834670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Evilnum.SP!MTB"
        threat_id = "2147834670"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Evilnum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {09 08 6f 1d 00 00 0a 6f 0a 00 00 0a 26 11 04 6f 1e 00 00 0a 09 6f 0b 00 00 0a 09 16 09 6f 1f 00 00 0a 6f 20 00 00 0a 26 38 d3 ff ff ff}  //weight: 4, accuracy: High
        $x_3_2 = "DataReceivedEventHandler" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

