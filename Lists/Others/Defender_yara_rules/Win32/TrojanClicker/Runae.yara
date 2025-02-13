rule TrojanClicker_Win32_Runae_A_2147643266_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Runae.A"
        threat_id = "2147643266"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Runae"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 41 49 4e 00 00 00 00 56 65 72 73 69 6f 6e 00 41 75 74 6f 49 45 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_2 = {43 72 65 61 74 65 70 72 6f 63 65 73 73 0a}  //weight: 1, accuracy: High
        $x_1_3 = "%sclick_log.asp?ad_url=%s" ascii //weight: 1
        $x_1_4 = "http://www.niudoudou.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

