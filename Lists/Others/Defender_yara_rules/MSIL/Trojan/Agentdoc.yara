rule Trojan_MSIL_Agentdoc_J_2147743445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agentdoc.J!ibt"
        threat_id = "2147743445"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agentdoc"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LinkZip.dll" wide //weight: 1
        $x_1_2 = "bd.hta" wide //weight: 1
        $x_1_3 = "mshta.exe" wide //weight: 1
        $x_1_4 = {72 3f 00 00 70 02 7b 02 00 00 04 72 0f 00 00 70 28 12 00 00 0a 28 19 00 00 0a 26}  //weight: 1, accuracy: High
        $x_1_5 = {02 7b 02 00 00 04 0e 04 28 12 00 00 0a 05 28 13 00 00 0a 28 04 00 00 06 28 14 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

