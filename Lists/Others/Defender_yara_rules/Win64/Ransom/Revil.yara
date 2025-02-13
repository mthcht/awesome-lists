rule Ransom_Win64_Revil_A_2147763664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Revil.A!MTB"
        threat_id = "2147763664"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Revil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Suxxesfully impersonated" ascii //weight: 1
        $x_1_2 = "Windir founded!" ascii //weight: 1
        $x_1_3 = "Manual switch to fast enc mode" ascii //weight: 1
        $x_1_4 = "Manual switch to full enc mode" ascii //weight: 1
        $x_1_5 = "start encrypt files" ascii //weight: 1
        $x_1_6 = "delete shadow copy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

