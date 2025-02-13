rule Trojan_MSIL_Ransom_BSG_2147814416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ransom.BSG!MSR"
        threat_id = "2147814416"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ransom"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "300"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "C:\\Desktop\\Cov-Locker\\Cov-Locker\\obj\\Release\\Cov-Locker.pdb" ascii //weight: 100
        $x_100_2 = "All your personal files have been encrypted using military grade encryption" ascii //weight: 100
        $x_100_3 = "Ooops, looks like you got the Virus!" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

