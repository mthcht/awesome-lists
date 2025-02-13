rule Trojan_MSIL_Tinuke_GA_2147820151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tinuke.GA!MTB"
        threat_id = "2147820151"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tinuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--no-sandbox --allow-no-sandbox-job --disable-3d-apis --disable-gpu --disable-d3d11 --user-data-dir=" ascii //weight: 1
        $x_1_2 = "cmd.exe /c start" ascii //weight: 1
        $x_1_3 = "-no-remote -profile" ascii //weight: 1
        $x_1_4 = "rundll32.exe shell32.dll" ascii //weight: 1
        $x_1_5 = "IsRelative=" ascii //weight: 1
        $x_1_6 = "http://" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

