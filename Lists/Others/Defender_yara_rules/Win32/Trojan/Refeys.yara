rule Trojan_Win32_Refeys_A_2147680134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Refeys.A"
        threat_id = "2147680134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Refeys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "&command=knock&username=" ascii //weight: 1
        $x_1_2 = {8b 43 0c 8b 00 8b 00 68 ?? ?? ?? ?? ff 37 89 45 ?? ff d6 85 c0 74 ?? 6a 50 ff d0 68 ?? ?? ?? ?? ff 37 66 89 45 ?? ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Refeys_B_2147682007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Refeys.B"
        threat_id = "2147682007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Refeys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&command=knock&username=" ascii //weight: 1
        $x_1_2 = "&command=deactivate&module=hvnc" ascii //weight: 1
        $x_1_3 = {8a 04 3e 3c 3b 74 0d 84 c0 74 09 42 88 04 33 46 3b f1 72 ec}  //weight: 1, accuracy: High
        $x_1_4 = "command=update_hid&new_hid=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

