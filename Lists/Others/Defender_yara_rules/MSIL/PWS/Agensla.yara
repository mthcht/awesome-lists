rule PWS_MSIL_Agensla_GA_2147780308_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Agensla.GA!MTB"
        threat_id = "2147780308"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agensla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "38"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/c netsh wlan show profiles" ascii //weight: 10
        $x_10_2 = "key=clear" ascii //weight: 10
        $x_10_3 = "Wifi Name" ascii //weight: 10
        $x_1_4 = "http://api.telegram.org/bot" ascii //weight: 1
        $x_1_5 = "DisableTaskMgr" ascii //weight: 1
        $x_1_6 = "000webhostapp.com/upload.php" ascii //weight: 1
        $x_1_7 = "https://pastebin.com/" ascii //weight: 1
        $x_1_8 = "encrypted_key\":\"(.*?)" ascii //weight: 1
        $x_1_9 = "/command" ascii //weight: 1
        $x_1_10 = "SELECT * FROM AntivirusProduct" ascii //weight: 1
        $x_1_11 = "virus has been hidden" ascii //weight: 1
        $x_1_12 = "\\Google\\Chrome\\User Data" ascii //weight: 1
        $x_1_13 = "schtasks /create /sc minute" ascii //weight: 1
        $x_1_14 = "\\WinRAR\\WinRAR.exe a -afzip" ascii //weight: 1
        $x_1_15 = ".png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

