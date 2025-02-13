rule Trojan_MSIL_Sdnldr_GG_2147753780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Sdnldr.GG!MTB"
        threat_id = "2147753780"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sdnldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DownloadFile" ascii //weight: 1
        $x_1_2 = "Spoofer.pdb" ascii //weight: 1
        $x_1_3 = "/spoofer.sys" ascii //weight: 1
        $x_1_4 = "https://cdn.discordapp.com/attachments/" ascii //weight: 1
        $x_1_5 = "Cleaning" ascii //weight: 1
        $x_1_6 = "Diskdrive" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

