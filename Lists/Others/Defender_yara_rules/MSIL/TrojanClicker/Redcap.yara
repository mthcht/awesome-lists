rule TrojanClicker_MSIL_Redcap_MBWE_2147928215_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Redcap.MBWE!MTB"
        threat_id = "2147928215"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dell.Asimov.Interop" ascii //weight: 1
        $x_1_2 = "Form1.Properties.Resources.resource" ascii //weight: 1
        $x_2_3 = "ttsqgzhj.exe" ascii //weight: 2
        $x_2_4 = "E3D5C0C330C2" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

