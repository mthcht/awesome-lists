rule Trojan_Win32_Moromi_NMO_2147893286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Moromi.NMO!MTB"
        threat_id = "2147893286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Moromi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "comm/datamodem" ascii //weight: 1
        $x_2_2 = "moromie/contents/index.html" ascii //weight: 2
        $x_2_3 = "\\SYSTEM32\\RAS\\RASPHONE.PBK" ascii //weight: 2
        $x_2_4 = "J   21ye" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

