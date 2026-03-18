rule Trojan_PowerShell_RemoteTem_AM_2147965117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/RemoteTem.AM!MTB"
        threat_id = "2147965117"
        type = "Trojan"
        platform = "PowerShell: "
        family = "RemoteTem"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 53 00 70 00 6c 00 69 00 74 00 28 00 29 00 3b 00 24 00 [0-8] 3d 00 5b 00 41 00 63 00 74 00 69 00 76 00 61 00 74 00 6f 00 72 00 5d 00 3a 00 3a 00 43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 28 00 5b 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 54 00 65 00 78 00 74 00 2e 00 53 00 74 00 72 00 69 00 6e 00 67 00 42 00 75 00 69 00 6c 00 64 00 65 00 72 00 5d 00 2c 00 24 00 [0-8] 2e 00 4c 00 65 00 6e 00 67 00 74 00 68 00 29 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_2 = {66 00 6f 00 72 00 65 00 61 00 63 00 68 00 28 00 24 00 [0-8] 20 00 69 00 6e 00 20 00 24 00 [0-8] 29 00 7b 00 24 00 [0-16] 2e 00 41 00 70 00 70 00 65 00 6e 00 64 00 28 00 5b 00 63 00 68 00 61 00 72 00 5d 00 5b 00 63 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 74 00 6f 00 69 00 6e 00 74 00}  //weight: 1, accuracy: Low
        $x_1_3 = "GCGG GAAG GTAC GTAC ACCG ATCT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

