rule Trojan_Win32_SantaStealer_YBG_2147961861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SantaStealer.YBG!MTB"
        threat_id = "2147961861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SantaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 01 ca 45 31 c8 44 89 4c 24 2c 44 8b 4c 24 34 44 31 d7 41 c1 c0 07 c1 c7 07 44 89 54 24 30 44 01 cb 44 89 44 24 38}  //weight: 2, accuracy: High
        $x_1_2 = {c1 c2 10 41 01 d4 45 31 e1 45 89 c8 41 c1 c0 0c 44 01 c3 31 da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

