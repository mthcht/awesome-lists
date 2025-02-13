rule Trojan_MSIL_Sambetoc_A_2147728349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Sambetoc.A"
        threat_id = "2147728349"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sambetoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Release\\autotouch.pdb" ascii //weight: 10
        $x_10_2 = "autosmbtouch" ascii //weight: 10
        $x_10_3 = "get_Esteemaudittouch_xml" ascii //weight: 10
        $x_10_4 = "get_Smbtouch_xml" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

