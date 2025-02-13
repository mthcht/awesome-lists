rule Trojan_Win32_Yedob_A_2147717225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yedob.A!dha"
        threat_id = "2147717225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yedob"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ad 3d 68 74 74 70 0f 85 ?? ?? 00 00 ac 66 ad 66 3d 2f 2f 0f 85 ?? ?? 00 00 89 f7 31 c9 80 3c 0f 3a}  //weight: 1, accuracy: Low
        $x_1_2 = {58 c9 c3 56 57 be ?? ?? ?? 00 89 f7 b9 ?? ?? 00 00 8a 06 32 47 ff 32 47 fe 88 06 4e 4f}  //weight: 1, accuracy: Low
        $x_1_3 = "accepted-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

