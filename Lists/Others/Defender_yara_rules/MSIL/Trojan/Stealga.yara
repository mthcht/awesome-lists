rule Trojan_MSIL_Stealga_DC_2147939989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealga.DC!MTB"
        threat_id = "2147939989"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealga"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "160"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "api.telegram.org/bot" ascii //weight: 100
        $x_10_2 = "Decrypt" ascii //weight: 10
        $x_10_3 = "User Data\\Default\\Local Extension Settings" ascii //weight: 10
        $x_10_4 = "chat_id" ascii //weight: 10
        $x_10_5 = "chrome.exe" ascii //weight: 10
        $x_10_6 = "msedge.exe" ascii //weight: 10
        $x_10_7 = "brave.exe" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

