rule TrojanSpy_MSIL_Yubaceds_A_2147642239_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Yubaceds.A"
        threat_id = "2147642239"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Yubaceds"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "New infection from Clinet Id:" wide //weight: 1
        $x_1_2 = "Infection logger from Clinet Id:" wide //weight: 1
        $x_1_3 = "Decay Public Logger Loaded At" wide //weight: 1
        $x_1_4 = "decay_sub_project." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

