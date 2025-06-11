rule Trojan_Win64_TestZero_A_2147943373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TestZero.A"
        threat_id = "2147943373"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TestZero"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 6f 62 6a 5c 52 65 6c 65 ?? 73 65 5c 52 75 6e 50 57 53 5f 6c 69 62 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = "CLR_lib.dll" ascii //weight: 1
        $x_1_3 = "RunPWS_lib.Program" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

