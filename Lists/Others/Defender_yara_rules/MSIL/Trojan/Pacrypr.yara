rule Trojan_MSIL_Pacrypr_A_2147743675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Pacrypr.A!MSR"
        threat_id = "2147743675"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pacrypr"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3J1ixBvR1r7VHgu5zJV7Xhv4moKh1cGfJA" wide //weight: 1
        $x_1_2 = "DecryptFs@protonmail.com" wide //weight: 1
        $x_10_3 = "open=usb.exe" wide //weight: 10
        $x_10_4 = "vssadmin.exe delete shadows /all /quiet & wmic.exe shadowcopy delete" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

