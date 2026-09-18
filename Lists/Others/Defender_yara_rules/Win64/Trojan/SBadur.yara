rule Trojan_Win64_SBadur_BA_2147978408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SBadur.BA!MTB"
        threat_id = "2147978408"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SBadur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8b 45 f8 48 8d 50 ff 48 8b 45 10 8b 04 90 89 45 f4 8b 45 f4 c1 e8 1e 31 45 f4 8b 45 f4 69 c0 ?? ?? ?? ?? 89 45 f4 48 8b 45 f8 89 c1 e8}  //weight: 5, accuracy: Low
        $x_1_2 = "powershell -Command \"Expand-Archive -Force -Path '%s' -Dest" ascii //weight: 1
        $x_1_3 = "\\certificate.vbs" ascii //weight: 1
        $x_1_4 = "\\certificate.lnk" ascii //weight: 1
        $x_1_5 = "C:\\Windows\\System32\\cmd.exe /c cd /d \"" ascii //weight: 1
        $x_1_6 = "\" && .\\uv.exe run sv.py" ascii //weight: 1
        $x_1_7 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-79] 2f 00 64 00 69 00 73 00 74 00 2f 00 73 00 76 00 2e 00 7a 00 69 00 70 00}  //weight: 1, accuracy: Low
        $x_1_8 = {68 74 74 70 3a 2f 2f [0-79] 2f 64 69 73 74 2f 73 76 2e 7a 69 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

