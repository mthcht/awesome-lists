rule Trojan_MSIL_DllHijack_GTD_2147958632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DllHijack.GTD!MTB"
        threat_id = "2147958632"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 16 0c 2b 21 06 08 72 ?? 05 00 70 07 72 ?? 05 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 9d 08 17 58 0c 08 06 8e 69 32 d9}  //weight: 10, accuracy: Low
        $x_1_2 = "igk.filexspace" ascii //weight: 1
        $x_1_3 = {57 00 69 00 6e 00 64 00 6f 00 77 00 53 00 74 00 79 00 6c 00 65 00 20 00 48 00 69 00 64 00 64 00 65 00 6e 00 20 00 2d 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 22 00 69 00 72 00 6d 00 20 00 27 00 68 00 74 00 74 00 70 00 [0-64] 20 00 7c 00 20 00 69 00 65 00 78 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

