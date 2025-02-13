rule Worm_Win32_Folstart_A_2147645143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Folstart.A"
        threat_id = "2147645143"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Folstart"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "S-1-5-31-1286970278978-5713669491-166975984-320\\Rotinom" wide //weight: 1
        $x_1_2 = {b9 81 00 00 00 33 c0 8d bc ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? f3 ab 66 ab b9 81 00 00 00 33 c0 8d ?? ?? ?? 8b 35 ?? ?? ?? ?? f3 ab 66 ab b9 82 00 00 00 33 c0 8d ?? ?? ?? 53 f3 ab 8d ?? ?? ?? 6a 1c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

