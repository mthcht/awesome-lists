rule Trojan_MSIL_BatLaunch_RPY_2147850593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BatLaunch.RPY!MTB"
        threat_id = "2147850593"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BatLaunch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hideit.bat" wide //weight: 1
        $x_1_2 = "rem GO GO GO" ascii //weight: 1
        $x_1_3 = "timeout /t 10 /nobreak" ascii //weight: 1
        $x_1_4 = "powershell -command" ascii //weight: 1
        $x_1_5 = "DownloadFile(" ascii //weight: 1
        $x_1_6 = "transfer.sh" ascii //weight: 1
        $x_1_7 = "SERVER.exe" ascii //weight: 1
        $x_1_8 = "start /b svc.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

