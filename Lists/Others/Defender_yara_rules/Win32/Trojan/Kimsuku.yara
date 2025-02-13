rule Trojan_Win32_Kimsuku_A_2147743404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kimsuku.A!MSR"
        threat_id = "2147743404"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kimsuku"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 3a 8d 52 01 80 e9 ?? 88 4a ff 83 e8 01 75 ef}  //weight: 1, accuracy: Low
        $x_1_2 = "komad" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

