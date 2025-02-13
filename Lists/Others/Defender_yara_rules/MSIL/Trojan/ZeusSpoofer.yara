rule Trojan_MSIL_ZeusSpoofer_RDA_2147903221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZeusSpoofer.RDA!MTB"
        threat_id = "2147903221"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZeusSpoofer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZeusSpooferBase" ascii //weight: 1
        $x_1_2 = "Spoofer menu test" ascii //weight: 1
        $x_1_3 = "Nemesis-45777" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

