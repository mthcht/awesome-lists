rule TrojanSpy_Win32_Cresyaf_A_2147718249_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Cresyaf.A"
        threat_id = "2147718249"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Cresyaf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 fb 11 0f 84 ?? ?? ?? ?? 80 fb 12 0f 84 ?? ?? ?? ?? 80 fb a0}  //weight: 1, accuracy: Low
        $x_1_2 = {5b 42 4f 54 49 44 3a 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

