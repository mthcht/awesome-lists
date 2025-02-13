rule Trojan_MSIL_Dordty_G_2147755917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dordty.G!MTB"
        threat_id = "2147755917"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dordty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "set_CheckForIllegalCrossThreadCalls" ascii //weight: 1
        $x_1_2 = "set_Credentials" ascii //weight: 1
        $x_1_3 = "get_Computer" ascii //weight: 1
        $x_1_4 = "set_PasswordChar" ascii //weight: 1
        $x_1_5 = "discord@gmail" wide //weight: 1
        $x_1_6 = "Discord Login Details" wide //weight: 1
        $x_1_7 = "https_discordapp.com" wide //weight: 1
        $x_1_8 = "C:\\Projekt Gandalf\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

