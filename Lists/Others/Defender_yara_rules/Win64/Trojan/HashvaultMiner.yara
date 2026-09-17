rule Trojan_Win64_HashvaultMiner_A_2147978346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/HashvaultMiner.A"
        threat_id = "2147978346"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "HashvaultMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "pool-side hashes" ascii //weight: 8
        $x_8_2 = "X-Hash-Difficulty" ascii //weight: 8
        $x_8_3 = "_RANDOMX_JITX86_STATIC" ascii //weight: 8
        $x_8_4 = "Running GhostRider benchmark on logical CPUs %u and %u (max scratchpad size %zu MB, huge pages %s)" ascii //weight: 8
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

