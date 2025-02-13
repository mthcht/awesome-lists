rule Trojan_VBS_Lindropr_A_2147735606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:VBS/Lindropr.A"
        threat_id = "2147735606"
        type = "Trojan"
        platform = "VBS: Visual Basic scripts"
        family = "Lindropr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".CreateShortcut(WScript.Arguments(1) & \".lnk\")" ascii //weight: 1
        $x_1_2 = "TargetPath = \"C:\\Windows\\System32\\cmd.exe" ascii //weight: 1
        $x_3_3 = "Arguments = \"/c _temp.prjx \" & chr(34) & WScript.Arguments(0) & chr(34)" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

