rule Backdoor_Linux_Xdr33_A_2147930754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Xdr33.A!MTB"
        threat_id = "2147930754"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Xdr33"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c9 ff 31 c0 bf e0 2f 0e 08 f2 ae f7 d1 80 b9 df 2f 0e 08 2f 74 ?? 57 57 68 a7 1c 0c 08 68 e0 2f 0e 08 e8 ?? ?? ?? ?? 83 c4 10}  //weight: 1, accuracy: Low
        $x_1_2 = {50 50 8d 85 b8 fd ff ff 50 ff 35 d8 78 0f 08 e8 ?? ?? ?? ?? 83 c4 10 85 c0 74 ?? 83 ec 0c 68 ad 41 0b 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

