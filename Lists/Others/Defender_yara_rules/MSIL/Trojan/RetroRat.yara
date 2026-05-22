rule Trojan_MSIL_RetroRat_ARL_2147969929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RetroRat.ARL!MTB"
        threat_id = "2147969929"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RetroRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "clay_Client.exe" wide //weight: 5
        $x_4_2 = "TooR_Net_Stealer.zip" wide //weight: 4
        $x_3_3 = "TooRNet_wallets.zip" wide //weight: 3
        $x_2_4 = "handleTooR_Net_Stealer" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

