rule Ransom_MSIL_SvinoLock_AMTB_2147974184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/SvinoLock!AMTB"
        threat_id = "2147974184"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SvinoLock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SvinoLock.pdb" ascii //weight: 1
        $x_1_2 = "SvinoLock.FormRansom" ascii //weight: 1
        $x_1_3 = "BlockedKeys" ascii //weight: 1
        $x_1_4 = "Locker by @skidware" ascii //weight: 1
        $x_1_5 = "System Blocked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

