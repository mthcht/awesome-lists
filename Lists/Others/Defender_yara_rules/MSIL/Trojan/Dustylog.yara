rule Trojan_MSIL_Dustylog_A_2147742476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dustylog.A"
        threat_id = "2147742476"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dustylog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2015-05-14\\NeD Worm Version 1 (2015-05-15)\\obj\\x86\\Debug\\log file.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

