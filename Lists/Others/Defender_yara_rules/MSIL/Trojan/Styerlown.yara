rule Trojan_MSIL_Styerlown_A_2147651531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Styerlown.A"
        threat_id = "2147651531"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Styerlown"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nadoProigrat" ascii //weight: 1
        $x_1_2 = "keyboardhook" ascii //weight: 1
        $x_1_3 = "RunSobyt" ascii //weight: 1
        $x_1_4 = "HideSendingFiles" ascii //weight: 1
        $x_1_5 = "C:\\WINDOWS\\svchost.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Styerlown_B_2147654884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Styerlown.B"
        threat_id = "2147654884"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Styerlown"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nadoProigrat" ascii //weight: 1
        $x_1_2 = "RunSobyt" ascii //weight: 1
        $x_1_3 = "UslovsBezZapyatoi" wide //weight: 1
        $x_1_4 = "taskmngr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

