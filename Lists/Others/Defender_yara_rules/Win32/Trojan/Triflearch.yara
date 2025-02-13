rule Trojan_Win32_Triflearch_A_2147692980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Triflearch.A"
        threat_id = "2147692980"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Triflearch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {68 00 6f 00 72 00 73 00 65 00 73 00 [0-24] 2e 00 66 00 69 00 6c 00 [0-24] 65 00 2d 00 74 00 6f 00 75 00 72 00 2e 00 72 00 75 00}  //weight: 4, accuracy: Low
        $x_4_2 = {2f 00 6e 00 6f 00 74 00 69 00 66 00 69 00 63 00 61 00 74 00 65 00 [0-6] 2e 00 70 00 68 00 70 00 3f 00 64 00 69 00 64 00 3d 00}  //weight: 4, accuracy: Low
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 68 00 6f 00 72 00 73 00 65 00 73 00 2e 00 67 00 72 00 65 00 65 00 6e 00 2d 00 6c 00 69 00 6e 00 6b 00 65 00 72 00 73 00 2e 00 72 00 75 00 2f 00 67 00 65 00 [0-24] 74 00 5f 00 69 00 6e 00 66 00 6f 00 3f 00 70 00 69 00 64 00 3d 00 37 00 38 00 33 00 34 00}  //weight: 1, accuracy: Low
        $x_1_4 = "http://horses.christmasrus.ru/get_info?pid=7834" wide //weight: 1
        $x_1_5 = {2f 00 76 00 5f 00 69 00 6e 00 73 00 74 00 61 00 [0-24] 6c 00 6c 00 3f 00 73 00 69 00 64 00 3d 00 31 00 33 00 33 00 39 00 38 00 26 00 67 00 75 00 69 00 64 00 3d 00 24 00 5f 00 5f 00 47 00 55 00 49 00 44 00 26 00 73 00 69 00 67 00 3d 00 24 00 5f 00 5f 00 53 00 49 00 47 00 26 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 3d 00 24 00 5f 00 5f 00 42 00 52 00 4f 00 57 00 53 00 45 00 52 00 26 00 6f 00 76 00 72 00 3d 00 24 00 5f 00 5f 00 [0-24] 4f 00 56 00 52 00}  //weight: 1, accuracy: Low
        $x_1_6 = {2f 00 76 00 5f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 3f 00 73 00 [0-24] 69 00 64 00 3d 00 31 00 33 00 33 00 39 00 38 00 26 00 73 00 69 00 67 00 3d 00 24 00 5f 00 5f 00 53 00 49 00 47 00 26 00 67 00 75 00 69 00 64 00 3d 00 24 00 5f 00 5f 00 47 00 55 00 49 00 44 00 [0-24] 26 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 3d 00 24 00 5f 00 5f 00 42 00 52 00 4f 00 57 00 53 00 45 00 52 00 26 00 6f 00 76 00 72 00 3d 00 24 00 5f 00 5f 00 4f 00 56 00 52 00}  //weight: 1, accuracy: Low
        $x_1_7 = "/v_install?sid=13398&ovr=$__OVR&browser=$__BROWSER&guid=$__GUID&sig=$__SIG" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Triflearch_B_2147693836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Triflearch.B"
        threat_id = "2147693836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Triflearch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 00 6e 00 6f 00 74 00 69 00 66 00 69 00 63 00 61 00 74 00 65 00 [0-6] 2e 00 70 00 68 00 70 00 3f 00 [0-24] 64 00 69 00 64 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 00 6e 00 6f 00 74 00 69 00 66 00 69 00 63 00 61 00 74 00 65 00 [0-6] 2e 00 70 00 68 00 70 00 [0-24] 3f 00 62 00 69 00 64 00 3d 00}  //weight: 1, accuracy: Low
        $x_2_3 = "?sid=13398&ovr=$__OVR&browser" wide //weight: 2
        $x_2_4 = ".ru/get_info?pid=7834" wide //weight: 2
        $x_2_5 = "/v_install?sid=13398&guid=$__GUID&sig=$__SIG&browser=$__BROWSER&ovr=$__OVR" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

