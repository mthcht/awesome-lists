rule Trojan_Win32_Iepatch_A_2147707757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Iepatch.A"
        threat_id = "2147707757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Iepatch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h.dll" ascii //weight: 1
        $x_1_2 = {68 6c 00 00 00 68 70 2e 64 6c}  //weight: 1, accuracy: High
        $x_5_3 = "hm32\\hystehws\\shindohC:\\W" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

