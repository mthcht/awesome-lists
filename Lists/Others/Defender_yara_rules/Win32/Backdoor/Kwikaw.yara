rule Backdoor_Win32_Kwikaw_A_2147672198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kwikaw.A"
        threat_id = "2147672198"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kwikaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "qawsed" wide //weight: 1
        $x_1_2 = "1207-GwF" wide //weight: 1
        $x_1_3 = "/c shutdown -r -t" wide //weight: 1
        $x_1_4 = {85 c0 0f 8e ?? ?? 00 00 33 c0 8a 8c 04 ?? ?? 00 00 80 f1 02 88 8c 04 ?? ?? 00 00 40 3d 00 08 00 00 7c ?? 8b 8c 24 ?? ?? 00 00 8d 41 ff 83 f8 09 77}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

