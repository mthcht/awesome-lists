rule Trojan_MSIL_ToxicEyeRAT_A_2147840914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ToxicEyeRAT.A!MTB"
        threat_id = "2147840914"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ToxicEyeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "TelegramRAT" ascii //weight: 2
        $x_2_2 = "1bcfe538-14f4-4beb-9a3f-3f9472794902" ascii //weight: 2
        $x_1_3 = "DownloadString" ascii //weight: 1
        $x_1_4 = "EnumDisplayDevices" ascii //weight: 1
        $x_1_5 = "GatewayIPAddressInformation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

