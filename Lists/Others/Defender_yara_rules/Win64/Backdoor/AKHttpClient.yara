rule Backdoor_Win64_AKHttpClient_A_2147947556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/AKHttpClient.A"
        threat_id = "2147947556"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "AKHttpClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 48 42 44 40 48 ?? ?? ?? ?? ?? ?? 75 6e 6b 6e 6f 77 6e 2e 6c 6f 63 61 6c 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

