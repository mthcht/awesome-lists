rule PWS_MSIL_Petun_A_2147642806_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Petun.A"
        threat_id = "2147642806"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Petun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "[First Run] Neptune -" wide //weight: 2
        $x_2_2 = "letting you know that your keylogger has been freshly installed" wide //weight: 2
        $x_1_3 = "Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f" wide //weight: 1
        $x_1_4 = "Attached is a screenshot of the victim" wide //weight: 1
        $x_1_5 = "RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Petun_B_2147646586_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Petun.B"
        threat_id = "2147646586"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Petun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Users\\Adrian\\Desktop\\NEW N0$crypter\\" ascii //weight: 1
        $x_1_2 = "Microsoft\\Protect\\Credentials" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

