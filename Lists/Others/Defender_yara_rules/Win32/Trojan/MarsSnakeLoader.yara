rule Trojan_Win32_MarsSnakeLoader_AA_2147978809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MarsSnakeLoader.AA!MTB"
        threat_id = "2147978809"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MarsSnakeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {48 03 c8 0f b6 01 41 88 01 44 88 11 41 0f b6 09 49 03 ca 0f b6 c1 0f b6 8c 04 ?? ?? ?? ?? 41 30 0b 49 ff c3 48 83 eb 01 75}  //weight: 11, accuracy: Low
        $x_4_2 = {41 0f b6 c8 49 8b c1 80 e1 ?? c0 e1 ?? 48 d3 e8 41 30 04 10 49 ff c0 49 83 f8}  //weight: 4, accuracy: Low
        $x_3_3 = "Function*71NOOkupFunction*71NOOkupFunction" ascii //weight: 3
        $x_2_4 = "load_http_" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

