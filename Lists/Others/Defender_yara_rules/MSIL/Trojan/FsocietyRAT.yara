rule Trojan_MSIL_FsocietyRAT_AMTB_2147964799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FsocietyRAT!AMTB"
        threat_id = "2147964799"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FsocietyRAT"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FsocietyRAT_Client.FsocietyAgent+<StealPasswords>" ascii //weight: 1
        $x_1_2 = "FsocietyRAT_Client.FsocietyAgent+<DestroySystem>" ascii //weight: 1
        $x_1_3 = "Diego Fsociety RAT.pdb" ascii //weight: 1
        $x_1_4 = "FsocietyRAT_Server" ascii //weight: 1
        $x_1_5 = "FSOCIETY WAS HERE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

