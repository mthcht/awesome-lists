rule Trojan_Win32_Qopus_A_2147696452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qopus.A"
        threat_id = "2147696452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qopus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Zombie_Get" ascii //weight: 1
        $x_1_2 = "121.40.173.38" wide //weight: 1
        $x_1_3 = "[ssend]" wide //weight: 1
        $x_1_4 = "Mozilla/6.0" wide //weight: 1
        $x_1_5 = "[zf]" wide //weight: 1
        $x_1_6 = {47 65 74 44 65 73 6b 74 6f 70 [0-16] 6a 69 65 71 75}  //weight: 1, accuracy: Low
        $x_1_7 = "getGTK" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

