rule Trojan_Win32_Phisr_A_2147682714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phisr.A"
        threat_id = "2147682714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phisr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {5b 50 49 44 20 25 64 20 28 25 73 29 5d [0-5] 41 44 44 52 20 25 70 3a 20 22 25 73 22 [0-6] 5b 45 4f 46 5d}  //weight: 3, accuracy: Low
        $x_3_2 = {2e 70 68 70 [0-5] 50 43 52 45 5f 45 52 52 4f 52 [0-5] 64 65 66 61 75 6c 74 [0-5] 25}  //weight: 3, accuracy: Low
        $x_3_3 = {50 4f 53 54 [0-5] 68 74 74 70 73 [0-5] 25 73 [0-5] 68 74 74 70 3a 2f 2f}  //weight: 3, accuracy: Low
        $x_1_4 = "((([4|5][0-9]{15})|([3|6]([0-9]){14}))[D=](?:0([7-9])|([1-4][0-9]))" ascii //weight: 1
        $x_1_5 = "(([0-9]\\0?){15,16}[D=]\\0?(?:0\\0?([7-9]\\0?)|([1-4]\\0?[0-9]\\0?))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

