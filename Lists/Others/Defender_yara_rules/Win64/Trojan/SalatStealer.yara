rule Trojan_Win64_SalatStealer_PSC_2147956566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SalatStealer.PSC!MTB"
        threat_id = "2147956566"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 47 67 41 64 41 42 30 41 48 41 41 63 77 41 36 41 43 38 41 4c 77 42 6e 41 47 6b 41 64 41 42 6f 41 48 55 41 59 67 41 75 41 47 4d 41 62 77 42 74 41 43 38 41 63 77 42 68 41 47 30 41 62 67 42 70 41 47 34 41 61 67 42 68 41 44 59 41 4e 67 41 32 41 43 38 [0-31] 41 48 49 41 59 51 42 33 41 43 38 41 63 67 42 6c 41 47 59 41 63 77 41 76 41 47 67 41 5a 51 42 68 41 47 51 41 63 77 41 76 41 47 30 41 59 51 42 70 41 47 34 41 4c 77}  //weight: 5, accuracy: Low
        $x_5_2 = "powershell -ExecutionPolicy Bypass -EncodedCommand %s" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

