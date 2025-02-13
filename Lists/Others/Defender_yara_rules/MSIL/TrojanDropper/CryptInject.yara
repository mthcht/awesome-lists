rule TrojanDropper_MSIL_CryptInject_EKD_2147748486_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/CryptInject.EKD!MTB"
        threat_id = "2147748486"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 09 11 09 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? 0c 72 ?? ?? ?? ?? 13 0b 06 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? 72 ?? ?? ?? ?? 11 0b 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 08 28 ?? ?? ?? ?? 06 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? 72 ?? ?? ?? ?? 11 0b 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "#Startup" wide //weight: 1
        $x_1_3 = "AddIt" wide //weight: 1
        $x_1_4 = "#prkill" wide //weight: 1
        $x_1_5 = "#CMDkill" wide //weight: 1
        $x_1_6 = "DisableCMD" wide //weight: 1
        $x_1_7 = "#taskkill" wide //weight: 1
        $x_1_8 = "DisableTaskMgr" wide //weight: 1
        $x_1_9 = "#restart" wide //weight: 1
        $x_1_10 = "shutdown" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

