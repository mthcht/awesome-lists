rule Trojan_MSIL_ICLoaader_RTS_2147926460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ICLoaader.RTS!MTB"
        threat_id = "2147926460"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ICLoaader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AMSIReaper" ascii //weight: 1
        $x_1_2 = "PROCESS_VM_OPERATION" ascii //weight: 1
        $x_1_3 = "v4.0.30319" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

