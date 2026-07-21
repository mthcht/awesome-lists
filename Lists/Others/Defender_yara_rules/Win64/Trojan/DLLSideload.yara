rule Trojan_Win64_DLLSideload_GPKF_2147974204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLSideload.GPKF!MTB"
        threat_id = "2147974204"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLSideload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {3c 49 6e 66 6f 55 72 6c 3e 68 74 74 70 3a 2f 2f 31 32 37 2e 30 2e 30 2e 31 2f 6e 6f 2d 75 70 64 61 74 65 3c 2f 49 6e 66 6f 55 72 6c 3e 0d 0a 20 20 3c 56 65 72 73 69 6f 6e 3e 31 2e 30 3c 2f 56 65 72 73 69 6f 6e 3e 0d 0a 20 20 3c 53 69 6c 65 6e 74 4d 6f 64 65 3e 79 65 73 3c 2f 53 69 6c 65 6e 74 4d 6f 64 65 3e 0d 0a 3c 2f 47 55 50 49 6e 70 75 74 3e 0d 0a 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 43 72 65 61 74 65 54 68 72 65 61 64 00 57 72 69 74 65 46 69 6c 65}  //weight: 15, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

