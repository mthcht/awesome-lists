rule HackTool_MSIL_Watson_SX_2147973490_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Watson.SX!MTB"
        threat_id = "2147973490"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Watson"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "120"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "[*] Finished. Found {0} potential vulnerabilities." ascii //weight: 30
        $x_30_2 = "[*] Finished. Found 0 vulnerabilities." ascii //weight: 30
        $x_20_3 = "CVE-2020-" ascii //weight: 20
        $x_20_4 = "CVE-2019-" ascii //weight: 20
        $x_10_5 = "[!] Could not retrieve Windows BuildNumber" ascii //weight: 10
        $x_10_6 = "[*] Enumerating installed KBs..." ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

