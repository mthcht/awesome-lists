rule TrojanSpy_MSIL_Mestepy_A_2147724778_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Mestepy.A!bit"
        threat_id = "2147724778"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mestepy"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://painel.moboymoboy.site/paste.php?pw=" wide //weight: 2
        $x_1_2 = "server.php?pw=" wide //weight: 1
        $x_1_3 = "getusermsg.php?hash=" wide //weight: 1
        $x_1_4 = "https://api.imgur.com/3/upload.xml" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

