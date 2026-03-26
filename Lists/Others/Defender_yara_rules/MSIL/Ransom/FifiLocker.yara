rule Ransom_MSIL_FifiLocker_AMTB_2147965611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FifiLocker!AMTB"
        threat_id = "2147965611"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FifiLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fifi_error.log" ascii //weight: 1
        $x_1_2 = ".fifi" ascii //weight: 1
        $x_1_3 = "fifi_key.bin" ascii //weight: 1
        $x_1_4 = "GenerateVictimID" ascii //weight: 1
        $x_1_5 = "FifiLockerMutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

