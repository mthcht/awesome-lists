rule Trojan_Win32_DriverLoader_ND_2147935828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DriverLoader.ND!MTB"
        threat_id = "2147935828"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DriverLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {33 c0 8d 4f 08 83 39 00 74 48 40 83 c1 10 83 f8 10 7c f2 68 ?? ?? 00 00 e8 ae 0f 00 00 8b d8 59 85 db 74 4f}  //weight: 3, accuracy: Low
        $x_2_2 = {4f c7 45 f0 ?? 00 00 00 8d 73 0c 6a 00}  //weight: 2, accuracy: Low
        $x_1_3 = "spoolsv.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

