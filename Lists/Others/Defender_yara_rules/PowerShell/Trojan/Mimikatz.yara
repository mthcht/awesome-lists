rule Trojan_PowerShell_Mimikatz_A_2147725502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Mimikatz.A"
        threat_id = "2147725502"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Mimikatz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $n_50_1 = "TaniumEndpointIndex.exe" wide //weight: -50
        $n_10_2 = "/mailto" wide //weight: -10
        $n_10_3 = "-deviceEventClassId" wide //weight: -10
        $n_10_4 = "-partnerName" wide //weight: -10
        $n_10_5 = "-grpname" wide //weight: -10
        $x_1_6 = "Invoke-Mimikatz" wide //weight: 1
        $x_1_7 = "Invoke-mimikittenz" wide //weight: 1
        $x_1_8 = "/putterpanda/mimikittenz/" wide //weight: 1
        $x_1_9 = {77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 29 00 2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 72 00 61 00 77 00 2e 00 67 00 69 00 74 00 68 00 75 00 62 00 75 00 73 00 65 00 72 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 [0-48] 20 00 2d 00 64 00 75 00 6d 00 70 00 63 00 72 00 65 00 64 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

