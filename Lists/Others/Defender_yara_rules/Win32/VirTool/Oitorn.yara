rule VirTool_Win32_Oitorn_A_2147615074_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Oitorn.A"
        threat_id = "2147615074"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Oitorn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MS08-067 Exploit for CN by EMM@ph4nt0m.org" ascii //weight: 1
        $x_1_2 = {7c c5 b9 06 00 00 00 be ?? ?? ?? ?? 8b fb b8 06 00 00 00 f3 a5 66 a5 8b 15 ?? ?? ?? ?? 89 14 2b 83 c5 04 48 75 f1 a1 ?? ?? ?? ?? be ?? ?? ?? ?? 89 04 2b 83 c5 04 8d 0c 2b 83 c5 04 c7 01 48 48 48 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

