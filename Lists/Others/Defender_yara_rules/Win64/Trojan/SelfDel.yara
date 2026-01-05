rule Trojan_Win64_SelfDel_MK_2147960489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SelfDel.MK!MTB"
        threat_id = "2147960489"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SelfDel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "65"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "[*] Starting malware sample" ascii //weight: 15
        $x_10_2 = "[*] XOR decrypting" ascii //weight: 10
        $x_15_3 = "[*] Found %s (PID: %d), injecting" ascii //weight: 15
        $x_5_4 = "[*] Loading file2.bin" ascii //weight: 5
        $x_5_5 = "[*] Decoding Base64" ascii //weight: 5
        $x_10_6 = "[*] Running from memory" ascii //weight: 10
        $x_5_7 = "[*] Cleaning up and exiting" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

