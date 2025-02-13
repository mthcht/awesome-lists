rule Trojan_Win32_Eikaf_A_2147730800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Eikaf.A"
        threat_id = "2147730800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Eikaf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "h2s(\"5B6175746F72756E5D" ascii //weight: 10
        $x_10_2 = {36 33 36 46 36 44 36 44 36 31 36 45 36 34 33 44 35 35 35 33 34 32 35 43 34 34 36 31 37 34 36 31 35 43 35 33 36 35 36 33 37 35 37 32 36 35 34 34 37 32 36 39 37 36 36 35 32 45 36 35 37 38 36 35 32 30 32 46 36 35 [0-112] 35 35 37 33 36 35 34 31 37 35 37 34 36 46 35 30 36 43 36 31 37 39 33 44 33 31 22 29}  //weight: 10, accuracy: Low
        $x_10_3 = {46 69 6c 65 45 78 69 73 74 28 [0-16] 29 20 3f 20 [0-16] 20 3a 20 22 64 65 6c 20 2f 66 20 2f 71 20}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

