rule Ransom_Win64_WormWiper_DA_2147924482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/WormWiper.DA!MTB"
        threat_id = "2147924482"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "WormWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files have been encrypted" ascii //weight: 1
        $x_1_2 = ".RANSOM_NOTE.txt" ascii //weight: 1
        $x_1_3 = "Encrypted:" ascii //weight: 1
        $x_1_4 = "Wiper" ascii //weight: 1
        $x_1_5 = "Ransomworm" ascii //weight: 1
        $x_1_6 = "Payload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

