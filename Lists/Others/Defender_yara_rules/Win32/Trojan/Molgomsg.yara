rule Trojan_Win32_Molgomsg_B_2147681446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Molgomsg.B"
        threat_id = "2147681446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Molgomsg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 e0 5b cf 3c ?? c7 45 e4 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {69 d2 51 2d 9e cc c1 c2 0f 69 d2 93 35 87 1b 33 c2}  //weight: 1, accuracy: High
        $x_1_3 = {00 77 69 6e 73 79 73 33 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

