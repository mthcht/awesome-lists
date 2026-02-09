rule Trojan_MSIL_TrojanProxy_AMTB_2147962643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TrojanProxy!AMTB"
        threat_id = "2147962643"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TrojanProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Welcome to WebProxy trojan produced by fLaSh" ascii //weight: 1
        $x_1_2 = "** Trojan IP [NEW]:" ascii //weight: 1
        $x_1_3 = "Trojaned Client" ascii //weight: 1
        $x_1_4 = "tr0j4ncr3at0r@trojan.com" ascii //weight: 1
        $x_1_5 = "W3bPr0xy Tr0j4n.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

