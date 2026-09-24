rule Trojan_Win64_CorvusMiner_MX_2147978748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CorvusMiner.MX!MTB"
        threat_id = "2147978748"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CorvusMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CorvusMiner" ascii //weight: 10
        $x_1_2 = "XMRig injection failed" ascii //weight: 1
        $x_1_3 = "[+] Payload written successfully" ascii //weight: 1
        $x_1_4 = "[*] GPU miner not enabled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

