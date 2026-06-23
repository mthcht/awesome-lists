rule Trojan_Win64_DLLInject_MCX_2147972182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLInject.MCX!MTB"
        threat_id = "2147972182"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 75 70 5f 75 74 69 6c 2e 64 6c 6c 00 5f 63 67 6f 5f 64 75 6d 6d 79 5f 65 78 70 6f 72 74 00 63 75 72 6c 5f 65 61 73 79 5f 63 6c 65 61 6e 75 70 00 63 75 72 6c 5f 65 61 73 79 5f 64 75 70 68 61 6e 64 6c 65 00 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

