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

rule Trojan_MSIL_PurelogStealer_SO_2147973523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PurelogStealer.SO!MTB"
        threat_id = "2147973523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PurelogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 cf 00 00 06 11 08 8d 1b 00 00 01 13 0a 7e 4a 00 00 04 02 1a 58 11 0a 16 11 08 28 2c 00 00 0a 28 71 00 00 0a 11 0a 16 11 0a 8e 69 6f 72 00 00 0a 13 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PurelogStealer_SN_2147981255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PurelogStealer.SN!MTB"
        threat_id = "2147981255"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PurelogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {00 02 6f 9d 00 00 0a 02 6f 9e 00 00 0a 5a 19 5a 03 28 7e 00 00 0a 0a 02 06 28 83 00 00 06 73 9f 00 00 0a 0b 2b 00 07 2a}  //weight: 4, accuracy: High
        $x_1_2 = "PrintingHouse.JobForm.resources" ascii //weight: 1
        $x_1_3 = "ReadPixelBytes" ascii //weight: 1
        $x_2_4 = "413 43B 430 43C 443 440 20" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

