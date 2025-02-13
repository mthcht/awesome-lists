rule Backdoor_MSIL_Ned_A_2147730472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Ned.A!MTB"
        threat_id = "2147730472"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ned"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "RESTARTME" wide //weight: 1
        $x_1_3 = "DEL-TEMP" wide //weight: 1
        $x_1_4 = "/log.php" wide //weight: 1
        $x_1_5 = "\\Last-Week-" wide //weight: 1
        $x_1_6 = "\\vmGuestLib.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

