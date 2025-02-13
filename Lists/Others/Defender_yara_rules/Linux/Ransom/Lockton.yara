rule Ransom_Linux_Lockton_A_2147919777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Lockton.A!MTB"
        threat_id = "2147919777"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Lockton"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "16RansomwareWindow" ascii //weight: 1
        $x_1_2 = {48 8d 15 bb 49 00 00 48 89 d1 ba 20 03 00 00 be dc 05 00 00 48 89 c7 e8 c3 b9 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

