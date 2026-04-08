rule Trojan_MSIL_PulsarRat_AMTB_2147966340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PulsarRat!AMTB"
        threat_id = "2147966340"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PulsarRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 70 00 73 00 31 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 6f 00 72 00 5f 00 [0-48] 2e 00 6c 00 6f 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = "RUNNER_URL" ascii //weight: 1
        $x_1_3 = "ps1p_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PulsarRat_GDB_2147966591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PulsarRat.GDB!MTB"
        threat_id = "2147966591"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PulsarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Pulsar.Common.dll" ascii //weight: 1
        $x_1_2 = "Messages.Administration.ReverseProxy" ascii //weight: 1
        $x_1_3 = "UserSupport.RemoteChat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

