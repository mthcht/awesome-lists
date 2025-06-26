rule Trojan_Win64_Topozuy_A_2147944702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Topozuy.A"
        threat_id = "2147944702"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Topozuy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "fBYlXF1MbDYmTh0tZQ==" ascii //weight: 2
        $x_2_2 = {00 52 78 67 77 58 6c 63 55 00}  //weight: 2, accuracy: High
        $x_1_3 = "decryptRKNSt7" ascii //weight: 1
        $x_1_4 = "launchTorRKNSt7" ascii //weight: 1
        $x_1_5 = "preprocessed_triage" ascii //weight: 1
        $x_1_6 = "checkNetworkAdapterMac" ascii //weight: 1
        $x_1_7 = "checkVmProcesses" ascii //weight: 1
        $x_1_8 = "hasHypervisorCpuFlag" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

