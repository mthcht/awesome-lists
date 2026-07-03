rule Trojan_PowerShell_SuspEnvExt_Z_2147972903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/SuspEnvExt.Z!MTB"
        threat_id = "2147972903"
        type = "Trojan"
        platform = "PowerShell: "
        family = "SuspEnvExt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5b 00 65 00 6e 00 76 00 69 00 72 00 6f 00 6e 00 6d 00 65 00 6e 00 74 00 5d 00 3a 00 3a 00 65 00 78 00 70 00 61 00 6e 00 64 00 65 00 6e 00 76 00 69 00 72 00 6f 00 6e 00 6d 00 65 00 6e 00 74 00 76 00 61 00 72 00 69 00 61 00 62 00 6c 00 65 00 73 00 28 00 [0-80] 2e 00 62 00 69 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_3 = "\\AppData\\Local" wide //weight: 1
        $x_1_4 = "); Move-Item -LiteralPath $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

