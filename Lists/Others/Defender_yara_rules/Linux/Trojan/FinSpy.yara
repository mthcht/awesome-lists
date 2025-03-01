rule Trojan_Linux_FinSpy_A_2147772447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/FinSpy.A!MTB"
        threat_id = "2147772447"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "FinSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 73 2f 2e 6b 64 65 [0-2] 2f 41 75 74 6f 73 74 61 72 74 2f 75 64 65 76 32 2e 73 68}  //weight: 1, accuracy: Low
        $x_1_2 = "%s/80C.dat" ascii //weight: 1
        $x_1_3 = "%s/.profile" ascii //weight: 1
        $x_2_4 = {20 24 7b 43 53 5f 46 4f 4e 54 5f 43 4f 4c 46 7d 20 24 7b 43 53 5f 46 4f 4e 54 5f 53 49 44 7d 20 26 26 20 24 7b 43 53 5f 46 4f 4e 54 5f 4c 4f 41 44 7d 20 26 26 20 24 7b 43 53 5f 46 4f 4e 54 5f 43 4f 4c 46 7d 20 2d 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c 20 32 3e 26 31 00 20 20 66 69 00 00 20 20 20 20 20 43 53 5f 46 4f 4e 54 5f 4c 4f 41 44 3d 24 28 66 6f 72 20 69 20 69 6e 20 60 65 63 68 6f 20 24 7b 43 53 5f 46 4f 4e 54 5f 49 44 7d 20 7c 73 65 64 20 27 73 2f 2e 2e 2f 26 20 2f 67 27 60 3b 20 20 64 6f 20 65 63 68 6f 20 22}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

