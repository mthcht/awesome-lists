rule Trojan_Win32_Teazodo_A_2147637575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Teazodo.A!dll"
        threat_id = "2147637575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Teazodo"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 6a 18 ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 ?? 8b 54 24 ?? 8b 44 24 ?? 52 56 50 ff 15}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 4e 0c 6a 00 6a 00 50 8b 86 88 01 00 00 50 6a 00 6a 00 ff d1}  //weight: 1, accuracy: High
        $x_1_3 = {83 c0 01 66 39 8c 47 80 08 00 00 75 f3 8d ?? 47 80 08 00 00 8d ?? 8e 08 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "%ls\\text.dll" wide //weight: 1
        $x_1_5 = "isnew=%d&LocalInfo=%ls %ls&szHostName=%ls" wide //weight: 1
        $x_1_6 = ":\\dev\\t0d0\\lab\\downloader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

