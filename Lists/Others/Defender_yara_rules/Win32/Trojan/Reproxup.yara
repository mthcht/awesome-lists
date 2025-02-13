rule Trojan_Win32_Reproxup_A_2147678797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reproxup.A"
        threat_id = "2147678797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reproxup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6d 6f 62 69 6c 65 2f 75 70 (64 61|67 72 61) 2e 70 68 70 3f 75 70 (6c 69|6d 61)}  //weight: 5, accuracy: Low
        $x_5_2 = {5c 52 65 61 6c 74 65 6b 73 ?? 00 00 ff ff ff ff ?? 00 00 00 5c 6c (61|69) 67 [0-10] 2e 74 78 74}  //weight: 5, accuracy: Low
        $x_1_3 = "r_pref(\"network.proxy.autoconfig_url\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

