rule Ransom_Win64_Radar_YAB_2147916722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Radar.YAB!MTB"
        threat_id = "2147916722"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Radar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 ba 0a 0a 52 41 44 41 52 0a 48 89 10 48 ba 0a 59 6f 75 72 20 6e 65}  //weight: 1, accuracy: High
        $x_1_2 = "data were encrypted" ascii //weight: 1
        $x_1_3 = "purchase RADAR Decryptor from us" ascii //weight: 1
        $x_1_4 = "rename encrypted files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

