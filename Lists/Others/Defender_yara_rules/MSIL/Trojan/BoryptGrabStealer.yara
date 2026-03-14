rule Trojan_MSIL_BoryptGrabStealer_B_2147964782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BoryptGrabStealer.B!AMTB"
        threat_id = "2147964782"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BoryptGrabStealer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "49,119,99,56,100,118,88,77,66,115,109,108,43,97,113,70,83,50,69,77,97,107,73,113,43,89,54,107" ascii //weight: 5
        $x_4_2 = "107,78,75,67,116,70,68,51,74,56,115,69,108,65,107,82,82,107,120,111" ascii //weight: 4
        $x_4_3 = "84,114,47,76,115,111,100,101,116,105,82,77,53,110,74,65,112,110,105" ascii //weight: 4
        $x_2_4 = "FromBase64String" ascii //weight: 2
        $x_3_5 = "WScript.Quit" ascii //weight: 3
        $x_2_6 = "C:\\TEMP\\" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

