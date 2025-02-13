rule Backdoor_MSIL_RogueRobin_YA_2147733886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/RogueRobin.YA!MTB"
        threat_id = "2147733886"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RogueRobin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\$fileUpload" wide //weight: 1
        $x_1_2 = "\\$ClearModules" wide //weight: 1
        $x_1_3 = "-U.txt" wide //weight: 1
        $x_1_4 = "-WindowStyle Hidden -exec bypass -command {0}" wide //weight: 1
        $x_1_5 = "gwmi -query \"select * from win32_BIOS where SMBIOSBIOSVERSION LIKE" wide //weight: 1
        $x_1_6 = "canonical name|mx|namerserver|mail server|address" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

