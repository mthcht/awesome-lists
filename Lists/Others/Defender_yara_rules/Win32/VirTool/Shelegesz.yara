rule VirTool_Win32_Shelegesz_A_2147961073_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Shelegesz.A"
        threat_id = "2147961073"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelegesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 56 57 33 ff 57 57 6a 02 57 57 68 00 00 00 10 68 18 20 40 00 ff ?? ?? ?? ?? ?? 8b f0 83 fe ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 56 18 33 ff 8b 46 30 8b 4e 2c 8b 36 89 45 ec 8b 42 3c 89 55 f8 89 75 e8 8b 5c 10 78 89 5d f4 85 db ?? ?? ?? ?? ?? ?? c1 e9 10 89 4d fc 85 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

