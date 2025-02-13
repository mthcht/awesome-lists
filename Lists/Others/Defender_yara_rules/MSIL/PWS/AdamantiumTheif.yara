rule PWS_MSIL_AdamantiumTheif_GA_2147773585_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/AdamantiumTheif.GA!MTB"
        threat_id = "2147773585"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AdamantiumTheif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Adamantium-Thief/master/Stealer/Stealer" ascii //weight: 10
        $x_1_2 = "libsodium.dll" ascii //weight: 1
        $x_1_3 = "browserCookies" ascii //weight: 1
        $x_1_4 = "Opera Software\\Opera Stable" ascii //weight: 1
        $x_1_5 = "Google\\Chrome" ascii //weight: 1
        $x_1_6 = "Yandex\\YandexBrowser" ascii //weight: 1
        $x_1_7 = "encrypted_key" ascii //weight: 1
        $x_1_8 = "os_crypt" ascii //weight: 1
        $x_1_9 = "Comodo\\Dragon" ascii //weight: 1
        $x_1_10 = "Not connected to internet!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

