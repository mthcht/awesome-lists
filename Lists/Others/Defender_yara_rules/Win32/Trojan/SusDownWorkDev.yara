rule Trojan_Win32_SusDownWorkDev_Z_2147968719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDownWorkDev.Z!MTB"
        threat_id = "2147968719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDownWorkDev"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "curl" wide //weight: 1
        $x_1_2 = {5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 [0-60] 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_1_3 = "workers.dev" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

