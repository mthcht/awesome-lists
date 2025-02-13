rule Trojan_MSIL_PripyatMiner_H_2147831869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PripyatMiner.H!MTB"
        threat_id = "2147831869"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PripyatMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System.Net.WebClient).DownloadFile" wide //weight: 1
        $x_1_2 = "cmd.exe /c schtasks /create /xml" wide //weight: 1
        $x_1_3 = "/tn \"GoogleUpdateTask\";cmd.exe /c del" wide //weight: 1
        $x_1_4 = "cmd.exe /c netsh interface ipv4 set dns name=" wide //weight: 1
        $x_1_5 = "/C choice /C Y /N /D Y /T 3 & Del" wide //weight: 1
        $x_1_6 = "/bot" wide //weight: 1
        $x_1_7 = "SELECT * FROM AntivirusProduct" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

