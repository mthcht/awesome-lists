rule TrojanSpy_MSIL_Rapzo_2147640828_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Rapzo"
        threat_id = "2147640828"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rapzo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Pain Logger" wide //weight: 2
        $x_2_2 = "msn_fuck_x" ascii //weight: 2
        $x_1_3 = "\\cdkeys.txt" wide //weight: 1
        $x_1_4 = "CIE7Passwords" ascii //weight: 1
        $x_1_5 = "CMSNMessengerPasswords" ascii //weight: 1
        $x_1_6 = "set_kbHook" ascii //weight: 1
        $x_1_7 = "DeleteMozillaCookies" ascii //weight: 1
        $x_1_8 = "cd_keytxt_Create" wide //weight: 1
        $x_1_9 = "Password.NET Messenger Service" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

