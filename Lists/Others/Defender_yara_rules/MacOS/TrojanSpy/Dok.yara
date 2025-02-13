rule TrojanSpy_MacOS_Dok_2147740590_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MacOS/Dok"
        threat_id = "2147740590"
        type = "TrojanSpy"
        platform = "MacOS: "
        family = "Dok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "This file is packed with the UPX executable packer" ascii //weight: 2
        $x_2_2 = "Ryan_Ltd.Software" ascii //weight: 2
        $x_1_3 = "Oleg Kosourov (Q9HZ55M855)1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

