rule DDoS_Win32_Dufeva_A_2147653385_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Dufeva.A"
        threat_id = "2147653385"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dufeva"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "clddosid=" ascii //weight: 1
        $x_1_2 = {b8 67 66 66 66 f7 e9 c1 fa 02 8b ?? c1 ?? 1f 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

