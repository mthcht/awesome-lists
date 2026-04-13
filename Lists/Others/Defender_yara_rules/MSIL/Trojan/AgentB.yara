rule Trojan_MSIL_AgentB_GXH_2147966936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AgentB.GXH!MTB"
        threat_id = "2147966936"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentB"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 72 04 00 70 28 ?? 00 00 0a 72 7e 04 00 70 28 ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_5_2 = {72 34 04 00 70 28 ?? 00 00 0a 72 42 04 00 70 28 ?? 00 00 0a 72 54 04 00 70 28 ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_5_3 = {72 16 04 00 70 28 ?? 00 00 0a 72 62 04 00 70 28 ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_4 = "RijndaelManaged" ascii //weight: 1
        $x_1_5 = "ClassLibrary3.dll" ascii //weight: 1
        $x_1_6 = "IsSandboxieInstalled" ascii //weight: 1
        $x_1_7 = "IsSandboxFilePresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

