rule HackTool_Win32_Daoak_A_2147729832_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Daoak.A"
        threat_id = "2147729832"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Daoak"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "software\\classes\\clsid\\{89565276-a714-4a43-912e-978b935edccc}" ascii //weight: 1
        $x_1_2 = "Software\\Classes\\DynamicWrapperX" ascii //weight: 1
        $x_1_3 = {0f b7 0c 48 b8 ?? ?? ?? ?? 01 c1 0f b7 0c 51 b8 ?? ?? ?? ?? 8d 1c 08 8b 46 08 8b 56 0c 8b 7d 1c 31 c9 ff d3 72 52}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 53 18 ba 00 04 00 00 83 f8 00 74 b6 81 fa 00 04 00 00 74 03 83 c2 02 68 ?? ?? ?? ?? 50 52 6a 00 6a 00 e8 ?? ?? ?? ?? 31 c0 eb b0}  //weight: 1, accuracy: Low
        $x_1_5 = {75 08 85 f6 74 42 89 f2 eb 05 85 f6 0f 44 f2 52 50 e8 ca 00 00 00 72 1b 89 d7 8b 4d fc ff 75 20 ff 75 1c ff 75 18 56 50 e8}  //weight: 1, accuracy: High
        $x_1_6 = {55 53 57 89 e5 81 ec 04 02 00 00 ff 75 10 e8 ?? ?? ?? ?? 85 c0 0f 84 84 00 00 00 89 c3 8b 7d 14 81 ff ff ff 00 00 76 25 8d bd fc fd ff ff 6a 00 6a 00 68 00 01 00 00 57 6a ff ff 75 14 6a 00 6a 00 e8 ?? ?? ?? ?? c6 87 ff 00 00 00 00 57 53 e8 ?? ?? ?? ?? 85 c0 74 0b 89 da f8 89 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

