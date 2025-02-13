rule Trojan_Win32_DLLInject_EM_2147895867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLInject.EM!MTB"
        threat_id = "2147895867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 69 62 6f 64 79 2e 74 77 2f 69 6d 61 67 65 73 2f 70 69 63 5f 62 72 61 6e 64 5f 30 ?? 2e 70 6e 67}  //weight: 10, accuracy: Low
        $x_10_2 = {6c 69 76 65 77 61 72 65 2d 61 2e 74 77 2f 69 6d 61 67 65 73 2f 74 6f 70 5f 70 72 6f 64 75 63 74 30 ?? 2e 70 6e 67}  //weight: 10, accuracy: Low
        $x_10_3 = {69 6c 68 61 2e 74 77 2f 69 6d 61 67 65 73 2f 74 6f 70 5f 70 72 6f 64 75 63 74 30 ?? 2e 70 6e 67}  //weight: 10, accuracy: Low
        $x_10_4 = {65 6d 65 74 6f 72 65 2d 74 77 2e 63 6f 6d 2f 69 6d 61 67 65 73 2f 74 6f 70 5f 70 72 6f 64 75 63 74 30 ?? 2e 70 6e 67}  //weight: 10, accuracy: Low
        $x_1_5 = "InternetConnect" ascii //weight: 1
        $x_1_6 = "ip-api.com" ascii //weight: 1
        $x_1_7 = "fdjYUGYb&%53321" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

