rule Trojan_MSIL_CsharpSploit_A_2147847188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CsharpSploit.A"
        threat_id = "2147847188"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CsharpSploit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "csharp_streamer.ms17_10" ascii //weight: 2
        $x_1_2 = "SharpSploitResultList" ascii //weight: 1
        $x_1_3 = "BuildImportAddressTable" ascii //weight: 1
        $x_1_4 = "LoginAnonymousAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

