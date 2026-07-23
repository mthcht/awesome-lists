rule Trojan_PowerShell_SuspPersist_ZQ_2147974351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/SuspPersist.ZQ!MTB"
        threat_id = "2147974351"
        type = "Trojan"
        platform = "PowerShell: "
        family = "SuspPersist"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "REG ADD" wide //weight: 1
        $x_1_3 = {72 00 65 00 67 00 2d 00 65 00 78 00 70 00 61 00 6e 00 64 00 5f 00 73 00 7a 00 20 00 2f 00 64 00 [0-16] 25 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2d 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 74 00 79 00 6c 00 65 00 [0-16] 24 00}  //weight: 1, accuracy: Low
        $x_1_5 = "(.'gp' 'HKCU:\\Software" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

