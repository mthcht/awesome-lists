rule Trojan_Win32_Sevfouive_A_2147742303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sevfouive.A"
        threat_id = "2147742303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sevfouive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 ff d3 85 c0 74 ?? 83 f8 01 74 ?? 83 f8 04 74 ?? 83 f8 05 74 ?? 83 f8 06 74 ?? 8d 44 ?? ?? 68 ?? ?? ?? ?? 50 ff d5 85 c0 74}  //weight: 1, accuracy: Low
        $x_10_2 = "c:\\windows\\sysexplr.exe" ascii //weight: 10
        $x_1_3 = {33 c0 66 a1 e6 65 40 00 83 f8 05 a3 ?? ?? ?? ?? 7c ?? c7 05 ?? ?? ?? ?? 05 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {66 a1 e6 65 40 00 8b 35 ?? ?? ?? ?? 66 3d 07 00 74 ?? 66 3d 11 00 74 ?? 66 3d 1b 00 75 10 6a 00 6a 00 6a 00 6a 00 ff d6 66 a1 e6 65 40 00}  //weight: 1, accuracy: Low
        $x_1_5 = {66 3d 04 00 74 ?? 66 3d 0e 00 74 ?? 66 3d 18 00 75 ?? 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 ff d6 e8 c8 ?? ?? ?? 85 c0 74 ?? e8 9f ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

