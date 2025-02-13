rule Trojan_MSIL_Growpia_AA_2147769836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Growpia.AA!MTB"
        threat_id = "2147769836"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Growpia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "screenshot.png" ascii //weight: 1
        $x_1_2 = "credentials.txt" ascii //weight: 1
        $x_1_3 = "pwd.txt" ascii //weight: 1
        $x_1_4 = "get_WebHook" ascii //weight: 1
        $x_1_5 = "PasteStealer" ascii //weight: 1
        $x_1_6 = "BruteforceHack" ascii //weight: 1
        $x_1_7 = "\\AppData\\Local\\Growtopia" ascii //weight: 1
        $x_1_8 = "echo j | del Trinity.bat" ascii //weight: 1
        $x_1_9 = "\\AppData\\Roaming\\Services.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

