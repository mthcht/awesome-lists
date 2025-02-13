rule Backdoor_MSIL_IModGetter_YA_2147734411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/IModGetter.YA!MTB"
        threat_id = "2147734411"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "IModGetter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net.tcp://{0}:23566/IModuleGetter" wide //weight: 1
        $x_1_2 = "%USERPROFILE%\\AppData\\Local\\Temp\\NetPlatform" wide //weight: 1
        $x_1_3 = "/C choice /C Y /N /D Y /T 3 & Del \"" wide //weight: 1
        $x_1_4 = "/C schtasks /create /tn \\Defaults\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

