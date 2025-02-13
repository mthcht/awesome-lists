rule VirTool_Win32_Catchyikn_A_2147611042_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Catchyikn.A"
        threat_id = "2147611042"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Catchyikn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 63 68 6f 69 63 65 25 22 3d 3d 22 31 22 20 67 6f 74 6f 20 54 43 50 0d 0a 69 66 20 2f 69 20 22 25 63 68 6f 69 63 65 25 22 3d 3d 22 32 22 20 67 6f 74 6f 20 53 59 4e 0d 0a 69 66 20 2f 69 20 22}  //weight: 1, accuracy: High
        $x_1_2 = "eol=P tokens=1 delims= \" %%i in (s1.txt)" ascii //weight: 1
        $x_1_3 = "[2008 Vip 1.0]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

