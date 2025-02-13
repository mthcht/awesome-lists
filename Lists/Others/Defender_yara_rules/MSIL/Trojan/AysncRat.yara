rule Trojan_MSIL_AysncRat_RF_2147841961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AysncRat.RF!MTB"
        threat_id = "2147841961"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AysncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {16 0a 2b 0d 02 06 02 06 91 03 59 d2 9c 06 17 58 0a 06 02 8e 69 32 ed}  //weight: 5, accuracy: High
        $x_1_2 = "fak_chea\\obj\\x86\\Release\\fak_chea.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AysncRat_RE_2147842331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AysncRat.RE!MTB"
        threat_id = "2147842331"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AysncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5f 5a fe 0c 14 00 20 14 00 00 00 64 58 fe 0e 14 00 20 c0 01 00 00 fe 0c 12 00 20 ff ff 0f 00 5f 5a fe 0c 12 00 20 14 00 00 00 64 59}  //weight: 5, accuracy: High
        $x_1_2 = "$85da9699-efff-4462-9567-08c6469da806" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

