rule Virus_Win32_Teazodo_A_2147637429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Teazodo.A"
        threat_id = "2147637429"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Teazodo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b0 73 b2 5c b1 64}  //weight: 2, accuracy: High
        $x_2_2 = {83 c1 01 83 c2 01 38 1c 31 74 f5 83 fa 37 77}  //weight: 2, accuracy: High
        $x_2_3 = {66 c7 86 d0 00 00 00 50 45 eb 0e 83 f8 ?? 75 09 66 c7 86 d8 00 00 00 50 45}  //weight: 2, accuracy: Low
        $x_2_4 = {80 38 c6 75 05 38 50 01 74 ?? 83 c1 01 83 c0 01 81 f9 80 00 00 00 72 e8 eb}  //weight: 2, accuracy: Low
        $x_2_5 = {6a 00 6a 18 ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 ?? 8b 54 24 ?? 8b 44 24 ?? 52 56 50 ff 15}  //weight: 2, accuracy: Low
        $x_1_6 = "s\\system32\\logonui.exe" wide //weight: 1
        $x_2_7 = "9F4ECEC8-4126-4a3a-8950-B8089C2B4832" wide //weight: 2
        $x_1_8 = "%c:\\Recycler\\" wide //weight: 1
        $x_2_9 = "lortnoCgubeDmetsySwZ" ascii //weight: 2
        $x_1_10 = "CgfUrl=http://" ascii //weight: 1
        $x_2_11 = "\\code\\downloaderinstaller\\" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

