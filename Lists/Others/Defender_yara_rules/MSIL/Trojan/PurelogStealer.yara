rule Trojan_MSIL_PurelogStealer_TC_2147929604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PurelogStealer.TC!MTB"
        threat_id = "2147929604"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PurelogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "https://www.chirreeirl.com/wp-panel/uploads/Wlvdlivs.mp3" ascii //weight: 2
        $x_1_2 = "sXgbzj+mkpC69C7JvcP3sQ==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PurelogStealer_MG_2147954966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PurelogStealer.MG!MTB"
        threat_id = "2147954966"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PurelogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 72 61 00 00 70 28 09 00 00 0a 6f 0a 00 00 0a 00 06 72 bb 00 00 70 28 09 00 00 0a 6f 0b 00 00 0a 00 06 6f 0c 00 00 0a 0b 73 0d 00 00 0a 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

