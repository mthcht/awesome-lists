rule Trojan_Win64_Blindspot_GV_2147920747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Blindspot.GV!MTB"
        threat_id = "2147920747"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Blindspot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Blindspot Agent" ascii //weight: 1
        $x_3_2 = "main.BlindspotPayload" ascii //weight: 3
        $x_1_3 = "main.RunningCampaign" ascii //weight: 1
        $x_1_4 = "main.bindataFileInfo" ascii //weight: 1
        $x_1_5 = "main.DecodedOutput" ascii //weight: 1
        $x_1_6 = "main.Screenshot" ascii //weight: 1
        $x_3_7 = "main.confFile=blindspot-agent.conf" ascii //weight: 3
        $x_3_8 = "main.encryptedVFS=blindspot.zip" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

