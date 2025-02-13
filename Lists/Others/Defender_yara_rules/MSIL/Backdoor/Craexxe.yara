rule Backdoor_MSIL_Craexxe_A_2147719752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Craexxe.A"
        threat_id = "2147719752"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Craexxe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "crypmap.chickenkiller.com" wide //weight: 8
        $x_1_2 = "DisableTaskManager = {0}" wide //weight: 1
        $x_1_3 = "\\Imminent\\Plugins\\" wide //weight: 1
        $x_1_4 = "KeyHook Ready." wide //weight: 1
        $x_1_5 = "set CDAudio door open" wide //weight: 1
        $x_1_6 = "set_UseShellExecute" ascii //weight: 1
        $x_1_7 = "set_RedirectStandardInput" ascii //weight: 1
        $x_1_8 = "KeyLoggerPacket" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

