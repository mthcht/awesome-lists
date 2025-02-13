rule Trojan_Win32_Lockit_GA_2147925376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lockit.GA!MTB"
        threat_id = "2147925376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lockit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {b8 0a 00 00 00 3b f0 0f 42 f0 8d 46 01 3d ff ff ff 7f 0f 87 c9 02 00 00 03 c0 3d 00 10 00 00 72 2f}  //weight: 5, accuracy: High
        $x_1_2 = "\\config.ini" wide //weight: 1
        $x_1_3 = "C:\\Users\\Administrator\\Desktop\\Dll3\\Release\\Dll3.pdb" ascii //weight: 1
        $x_1_4 = "CreateBrowser" ascii //weight: 1
        $x_1_5 = "\\config.dat" wide //weight: 1
        $x_1_6 = "Lockit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

