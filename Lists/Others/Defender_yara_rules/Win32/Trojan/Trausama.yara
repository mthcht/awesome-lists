rule Trojan_Win32_Trausama_A_2147642067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trausama.A"
        threat_id = "2147642067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trausama"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b fe 8a 84 17 ?? ?? ?? ?? 8d 8a ?? ?? ?? ?? 34 9d 42 3b d3 88 01 7c}  //weight: 1, accuracy: Low
        $x_1_2 = "95.168.172.46" ascii //weight: 1
        $x_1_3 = "DEFSER" ascii //weight: 1
        $x_1_4 = {4d 4f 52 45 00 00 00 00 77 62 2b 00 72 62 00 00 4e 4f 52 52}  //weight: 1, accuracy: High
        $x_1_5 = "Kernel Page Fault xxxxxxh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

