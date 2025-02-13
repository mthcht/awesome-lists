rule Trojan_Win64_Guidownloader_A_2147911694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Guidownloader.A"
        threat_id = "2147911694"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Guidownloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 88 44 24 18 88 54 24 10 48 89 4c 24 08 0f be 44 24 10 f7 d0 0f ?? 4c 24 18 23 c1 0f be 4c 24 10 0f be 54 24 18 f7 d2 23 ca 0b c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

