rule Ransom_Win64_Shinyspider_CG_2147955731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Shinyspider.CG!MTB"
        threat_id = "2147955731"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Shinyspider"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "main.encryptFile" ascii //weight: 5
        $x_5_2 = "main.deobfuscateData" ascii //weight: 5
        $x_5_3 = "main.killBlacklistedServices" ascii //weight: 5
        $x_5_4 = "main.encryptNetworkShares" ascii //weight: 5
        $x_5_5 = "main.deleteWindowsEventLogs" ascii //weight: 5
        $x_5_6 = "main.deleteSelfViaWM" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

