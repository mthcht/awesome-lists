rule VirTool_Win32_Telzsor_B_2147841303_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Telzsor.B!MTB"
        threat_id = "2147841303"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Telzsor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 c8 83 c0 10 8b 4d f8 89 41 20 eb 46}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d ac 51 68 00 10 02 00 8b 55 ac 52 68 04 20 00 80 8b 45 d0 50 ff}  //weight: 1, accuracy: High
        $x_1_3 = {83 c4 04 8b 4d a4 89 8d 0c fc ff ff 89 85 04 fc ff ff 89 95 08 fc ff ff 8b 95 0c fc ff ff 8b 82 18 02 00 00 3b 85 04 fc ff ff 75 38}  //weight: 1, accuracy: High
        $x_1_4 = {c7 45 c4 00 00 00 00 c7 45 b8 00 00 00 00 8b f4 68 00 10 02 00 6a 08 8b fc ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

