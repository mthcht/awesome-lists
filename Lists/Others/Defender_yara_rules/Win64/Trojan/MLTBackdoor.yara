rule Trojan_Win64_MLTBackdoor_A_2147978623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MLTBackdoor.A!AMTB"
        threat_id = "2147978623"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MLTBackdoor"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "powwowski.com" ascii //weight: 3
        $x_2_2 = {70 61 79 6c 6f 61 64 73 2f [0-48] 2e 7a 69 70}  //weight: 2, accuracy: Low
        $x_1_3 = "powershell -WindowStyle Hidden -NonInteractive -Command \"Expand-Archive -LiteralPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

