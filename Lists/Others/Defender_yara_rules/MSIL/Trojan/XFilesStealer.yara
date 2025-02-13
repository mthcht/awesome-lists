rule Trojan_MSIL_XFilesStealer_NEAA_2147834185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XFilesStealer.NEAA!MTB"
        threat_id = "2147834185"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XFilesStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "nltest /domain_trusts /all_trusts" wide //weight: 5
        $x_5_2 = "net group \"Domain Admins\" /domain" wide //weight: 5
        $x_5_3 = "/C choice /C Y /N /D Y /T 3 & Del" wide //weight: 5
        $x_5_4 = "Del LAG1 && Del LAG2" wide //weight: 5
        $x_4_5 = "shfolder.dll" wide //weight: 4
        $x_4_6 = "net view /all" wide //weight: 4
        $x_2_7 = "cmd.exe" wide //weight: 2
        $x_2_8 = "request is not a http request" wide //weight: 2
        $x_2_9 = "Finish!" wide //weight: 2
        $x_1_10 = "set_WindowStyle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

