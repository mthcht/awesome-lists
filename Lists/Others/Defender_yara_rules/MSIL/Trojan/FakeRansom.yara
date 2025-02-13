rule Trojan_MSIL_FakeRansom_PA_2147754743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FakeRansom.PA!MTB"
        threat_id = "2147754743"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FakeRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MassFileRenamer_fakeransomware" wide //weight: 1
        $x_1_2 = "your files have been encrypted" wide //weight: 1
        $x_1_3 = "Wana Decrypt0r" wide //weight: 1
        $x_1_4 = "bitcoin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

