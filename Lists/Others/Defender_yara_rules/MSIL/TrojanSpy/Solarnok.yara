rule TrojanSpy_MSIL_Solarnok_A_2147688851_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Solarnok.A"
        threat_id = "2147688851"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Solarnok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "runkeylog" ascii //weight: 1
        $x_1_2 = "KnockResponseCommand" ascii //weight: 1
        $x_1_3 = "AddToStartup" ascii //weight: 1
        $x_1_4 = "GetWallet" ascii //weight: 1
        $x_1_5 = "Botinfo" ascii //weight: 1
        $x_1_6 = "KeyLogger" ascii //weight: 1
        $x_1_7 = "PasswordGrabber" ascii //weight: 1
        $x_1_8 = "/C ping -n 3 127.0.0.1 > nul & del /A:SH \"" wide //weight: 1
        $x_1_9 = ",\"passwords\":[" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

