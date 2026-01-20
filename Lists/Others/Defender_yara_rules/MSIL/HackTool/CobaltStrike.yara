rule HackTool_MSIL_CobaltStrike_EM_2147961403_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/CobaltStrike.EM!MTB"
        threat_id = "2147961403"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "upload beacon.exe c:\\beacon.exe" ascii //weight: 2
        $x_2_2 = "[+]Upload file done!" ascii //weight: 2
        $x_1_3 = "wmi = [wmiclass]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

