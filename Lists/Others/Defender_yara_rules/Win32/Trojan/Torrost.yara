rule Trojan_Win32_Torrost_A_2147682604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Torrost.A"
        threat_id = "2147682604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Torrost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 4c cc 00 00 ff d0 0f b7 c8 51 68 7f 00 00 01 e8 ?? ?? ff ff 8b f0 85 f6 0f 84 ?? 01 00 00 8b 15 ?? ?? ?? ?? 8b [0-5] 6a 00 6a 03}  //weight: 10, accuracy: Low
        $x_1_2 = ".onion/ct4.php" ascii //weight: 1
        $x_1_3 = "SocksPort 52300 --FascistFirewall 1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

