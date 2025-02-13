rule Trojan_MSIL_NetWired_ACE_2147751749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NetWired.ACE!MTB"
        threat_id = "2147751749"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NetWired"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GalliumSPICE.exe" wide //weight: 1
        $x_1_2 = "AWWdVFTnJQJzjCmHzJgJsXlipDhA.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

