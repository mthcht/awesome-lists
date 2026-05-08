rule TrojanDownloader_MSIL_Jaik_PZR_2147968861_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Jaik.PZR!MTB"
        threat_id = "2147968861"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "https://github.com/darkislivenow-cloud/DarkDevPC/releases/download/Payload/SystemOptions.zip" ascii //weight: 5
        $x_5_2 = "https://github.com/ayomide940-prog/o365Loads/releases/download/1/Adobe.zip" ascii //weight: 5
        $x_1_3 = "New-Item -ItemType Directory -Path \"C:\\Temp\"" ascii //weight: 1
        $x_1_4 = "attrib +h +r $zipFile" ascii //weight: 1
        $x_1_5 = "Start-Sleep -Milliseconds (Get-Random -Minimum 300 -Maximum 1500)" ascii //weight: 1
        $x_1_6 = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

