rule Ransom_MSIL_ShinigamiLocker_A_2147729961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/ShinigamiLocker.A"
        threat_id = "2147729961"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShinigamiLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Any attemt on closing or deliting this software will damage your computer!" wide //weight: 1
        $x_1_2 = "BTC BITCOIN WALLET FOR PAYMENT 1MBPSrn46eEVBHoypyjgfdCCf5DQxQsx3f" wide //weight: 1
        $x_1_3 = "07e699b9-1717-41b5-af3c-7210d4fbd080" ascii //weight: 1
        $x_1_4 = "\\rANSOM\\rANSOM\\obj\\Sanyasteakler\\rANSOM.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

