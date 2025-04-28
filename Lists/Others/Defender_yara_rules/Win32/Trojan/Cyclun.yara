rule Trojan_Win32_Cyclun_ECP_2147940177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cyclun.ECP!MTB"
        threat_id = "2147940177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cyclun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {b9 f7 68 00 00 99 f7 f9 6a 00 80 c2 02 30 96}  //weight: 5, accuracy: High
        $x_5_2 = {8d 4b 01 f7 e6 33 db 46 c1 ea 02 8d 04 92 3b f8 0f 45 d9 81 fe}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

