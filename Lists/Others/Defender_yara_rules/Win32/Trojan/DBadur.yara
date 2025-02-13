rule Trojan_Win32_DBadur_GPA_2147904985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DBadur.GPA!MTB"
        threat_id = "2147904985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DBadur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "x-scripts.online/file" ascii //weight: 1
        $x_1_2 = "A_ScriptDir" ascii //weight: 1
        $x_1_3 = "URLDownloadToFile" ascii //weight: 1
        $x_1_4 = "injectData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

