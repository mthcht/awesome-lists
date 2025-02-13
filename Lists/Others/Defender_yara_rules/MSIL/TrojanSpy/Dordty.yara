rule TrojanSpy_MSIL_Dordty_AA_2147755905_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Dordty.AA!MTB"
        threat_id = "2147755905"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dordty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "OxygenInjector" ascii //weight: 1
        $x_1_2 = "\\inject'" wide //weight: 1
        $x_1_3 = "process.env.anarchyHook = '" wide //weight: 1
        $x_1_4 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Discord Inc\\Discord.lnk" wide //weight: 1
        $x_1_5 = "AnarchyGrabber" wide //weight: 1
        $x_1_6 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-16] 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 [0-16] 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Dordty_AB_2147755906_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Dordty.AB!MTB"
        threat_id = "2147755906"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dordty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\discord\\Local Storage\\leveldb\\" wide //weight: 1
        $x_1_2 = {44 69 73 63 6f 72 64 2d 54 6f 6b 65 6e 2d 47 72 61 62 62 65 72 2d 6d 61 73 74 65 72 [0-32] 44 69 73 63 6f 72 64 54 6f 6b 65 6e 47 72 61 62 62 65 72}  //weight: 1, accuracy: Low
        $x_1_3 = "Token.txt" wide //weight: 1
        $x_1_4 = "Token=" wide //weight: 1
        $x_1_5 = "SearchForFile" ascii //weight: 1
        $x_1_6 = "DiscordTokenGrabber.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

