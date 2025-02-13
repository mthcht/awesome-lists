rule Worm_Win32_Banealapay_A_2147647605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Banealapay.A"
        threat_id = "2147647605"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Banealapay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "InfectDrive" ascii //weight: 1
        $x_1_2 = "GetAliveHosts" ascii //weight: 1
        $x_1_3 = "InfectSubnet" ascii //weight: 1
        $x_1_4 = {49 00 6e 00 69 00 63 00 69 00 6f 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 61 00 73 00 5c 00 49 00 6e 00 69 00 63 00 69 00 6f 00 [0-32] 63 00 6f 00 70 00 79 00 [0-32] 5c 00 75 00 70 00 64 00 61 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {66 05 01 00 66 89 45 ?? e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_6 = {66 2d 11 00 0f bf c0 50 8d 45 ?? 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

