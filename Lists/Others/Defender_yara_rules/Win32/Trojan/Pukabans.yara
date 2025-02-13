rule Trojan_Win32_Pukabans_D_2147730983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pukabans.D!!Pukabans.D!dha"
        threat_id = "2147730983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pukabans"
        severity = "Critical"
        info = "Pukabans: an internal category used to refer to some threats"
        info = "D: an internal category used to refer to some threats"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 ff 00 04 00 00 75 ?? 33 db 53 53 53 68 ?? ?? ?? ?? 53 53 [0-1] e8 [0-16] 81 ff 63 04 00 00 75}  //weight: 10, accuracy: Low
        $x_10_2 = {81 ff 64 04 00 00 75}  //weight: 10, accuracy: High
        $x_10_3 = {81 ff 05 04 00 00 75}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

