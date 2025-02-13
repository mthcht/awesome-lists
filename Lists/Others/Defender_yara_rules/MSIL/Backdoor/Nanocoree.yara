rule Backdoor_MSIL_Nanocoree_2147764052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Nanocoree!MTB"
        threat_id = "2147764052"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocoree"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "NanoCore" ascii //weight: 5
        $x_1_2 = "ClientSettingChanged" ascii //weight: 1
        $x_1_3 = "SendToServer" ascii //weight: 1
        $x_1_4 = "DisableProtection" ascii //weight: 1
        $x_1_5 = "QueueUserWorkItem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

