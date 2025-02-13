rule Trojan_Win64_BManager_E_2147912748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BManager.E"
        threat_id = "2147912748"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BManager"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 70 79 69 5f 72 74 68 5f 69 6e 73 70 65 63 74 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 4f ae 00 00 ?? ?? 00 00 ?? ?? 01 73 62 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

