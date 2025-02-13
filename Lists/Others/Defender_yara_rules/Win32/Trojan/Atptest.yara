rule Trojan_Win32_Atptest_A_2147725380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Atptest.A"
        threat_id = "2147725380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Atptest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=== BEGIN WDATP TEST FILE ===" ascii //weight: 1
        $x_1_2 = "584e459b-64da-4996-a335-abebd2f0e771" ascii //weight: 1
        $x_1_3 = "281b5691-f410-4a40-ae7e-7bfe8d1c8a49" ascii //weight: 1
        $x_1_4 = "8d1fcaed-1f1d-48ce-9488-a83f5e83f464" ascii //weight: 1
        $x_1_5 = "=== END WDATP TEST FILE ===" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

