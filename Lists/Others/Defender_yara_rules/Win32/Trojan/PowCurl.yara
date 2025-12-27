rule Trojan_Win32_PowCurl_DA_2147945703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowCurl.DA!MTB"
        threat_id = "2147945703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowCurl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "120"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 63 00 64 00 20 00 63 00 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00 5c 00 [0-50] 5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 5c 00 74 00 65 00 6d 00 70 00}  //weight: 100, accuracy: Low
        $x_10_2 = {26 00 26 00 20 00 63 00 75 00 72 00 6c 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-60] 2e 00 70 00 68 00 70 00}  //weight: 10, accuracy: Low
        $x_10_3 = "&& powershell -ExecutionPolicy Bypass -File" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

