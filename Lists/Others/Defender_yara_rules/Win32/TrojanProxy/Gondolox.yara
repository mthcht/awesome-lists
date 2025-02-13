rule TrojanProxy_Win32_Gondolox_A_2147678708_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Gondolox.A"
        threat_id = "2147678708"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gondolox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\x00ProxyServer\\x00ProxyEnable\\x00=" ascii //weight: 1
        $x_1_2 = {53 75 62 6a 65 63 74 3a 20 25 73 0d 0a [0-8] 25 73 [0-6] 50 4f 53 54 20 68 74 74 70 3a 2f 2f 25 73 25 73 20 48 54 54 50 2f 31 2e 31 0d}  //weight: 1, accuracy: Low
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "bestcrypt_update" ascii //weight: 1
        $x_1_5 = {0f b6 1c 39 0f b6 d2 69 d2 ?? ?? ?? ?? 03 db 8d 2c 10 03 ed 33 dd 33 d8 81 c3 ?? ?? ?? ?? 83 c1 01 3b ce 8b c3 72 ?? 8b 5c 24 14 5d 89 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

