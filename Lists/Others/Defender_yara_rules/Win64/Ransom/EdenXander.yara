rule Ransom_Win64_EdenXander_AEX_2147972743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/EdenXander.AEX!MTB"
        threat_id = "2147972743"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "EdenXander"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "support@edenxander.onion" ascii //weight: 4
        $x_3_2 = "EDEN-XANDER Ransomware" ascii //weight: 3
        $x_1_3 = ".locked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

