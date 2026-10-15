rule Trojan_MSIL_PhantomGate_SX_2147972023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PhantomGate.SX!MTB"
        threat_id = "2147972023"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PhantomGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_30_1 = {14 0a 06 14 28 03 00 00 0a 26 28 04 00 00 0a 02 6f 05 00 00 0a 2a}  //weight: 30, accuracy: High
        $x_10_2 = "PhantomGate" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PhantomGate_A_2147978068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PhantomGate.A!MTB"
        threat_id = "2147978068"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PhantomGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 03 00 00 0a 0a 06 14 28 04 00 00 0a 26 28 05 00 00 0a 02 6f 06 00 00 0a 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PhantomGate_A_2147978068_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PhantomGate.A!MTB"
        threat_id = "2147978068"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PhantomGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_12_1 = {28 03 00 00 0a 0a 06 14 28 04 00 00 0a 26 28 05 00 00 0a 02 6f 06 00 00 0a}  //weight: 12, accuracy: High
        $x_3_2 = "PhantonNOtg" ascii //weight: 3
        $x_3_3 = "PhantomGate" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_12_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_PhantomGate_A_2147978068_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PhantomGate.A!MTB"
        threat_id = "2147978068"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PhantomGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {28 03 00 00 0a 0a 06 14 28 04 00 00 0a 26 28 05 00 00 0a 02 6f 06 00 00 0a 2a}  //weight: 5, accuracy: High
        $x_5_2 = "PhantomGate" ascii //weight: 5
        $x_1_3 = "LoadAssembly" ascii //weight: 1
        $x_1_4 = "GetExecutingAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

