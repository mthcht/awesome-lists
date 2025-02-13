rule Backdoor_MSIL_BlackSpider_G_2147742429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/BlackSpider.G!MTB"
        threat_id = "2147742429"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlackSpider"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\BlackSpider.Installer\\" ascii //weight: 1
        $x_1_2 = "AntivirusProduct" ascii //weight: 1
        $x_1_3 = "pathToSignedProductExe" ascii //weight: 1
        $x_1_4 = "IPEnabled = TRUE" ascii //weight: 1
        $x_1_5 = "/C Y /N /D Y /T" ascii //weight: 1
        $x_1_6 = "schtasks.exe" ascii //weight: 1
        $x_1_7 = "ip-api.com/json/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

