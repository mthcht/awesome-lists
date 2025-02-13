rule Trojan_Win32_Tepeceed_A_2147681122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepeceed.A"
        threat_id = "2147681122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepeceed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 50 0f a2 33 f8 66 2b f9 c1 ef 05 c1 cf 07 36 83 3c 24 01 74 02 03 fb 33 f9 58 83 f8 02 75 e0}  //weight: 1, accuracy: High
        $x_1_2 = "decept_mutex_" ascii //weight: 1
        $x_1_3 = "[%04d.%02d.%02d]_[.%02d.%02d.%02d].jpg" wide //weight: 1
        $x_1_4 = "%04d.%02d.%02d.%02d.%02d.%02d.jpg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

