rule Trojan_Win32_RootkitRevealer_SJ_2147965388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RootkitRevealer.SJ!MTB"
        threat_id = "2147965388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RootkitRevealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 14 6a 5c 89 04 8e 8b 54 24 18 8b 04 96 50 e8 c3 2d 00 00 66 89 68 02 8b 44 24 1c 83 c4 0c 40 89 44 24 10 8d 84 24 38 04 00 00 50 68 04 01 00 00 ff 15 30 91 cf 00 8d 8c 24 38 04 00 00 68 90 dd cf 00 8d 54 24 18}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4c 24 14 6a 5c 89 04 8e 8b 54 24 18 8b 04 96 50 e8 c3 2d 00 00 66 89 68 02 8b 44 24 1c 83 c4 0c 40 89 44 24 10 8d 84 24 38 04 00 00 50 68 04 01 00 00 ff 15 30 91 b8 00 8d 8c 24 38 04 00 00 68 90 dd b8 00 8d 54 24 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_RootkitRevealer_SL_2147967721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RootkitRevealer.SL!MTB"
        threat_id = "2147967721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RootkitRevealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Error copying image to random service image file" ascii //weight: 1
        $x_1_2 = "cmd.exe /c chcp 65001 && set DIRCMD= && \"cmd /c dir /4 /a /s %s\\ > %s" ascii //weight: 1
        $x_1_3 = "Save RootkitRevealer Output" ascii //weight: 1
        $x_1_4 = "Software\\Sysinternals\\RootkitRevealer" ascii //weight: 1
        $x_1_5 = "Unable to install RootkitRevealer service" ascii //weight: 1
        $x_1_6 = "RootkitRevealer must be run from the console" ascii //weight: 1
        $x_1_7 = "RootkitRevealer v1.7" ascii //weight: 1
        $x_1_8 = "You may not redistribute RootkitRevealer without express written permission" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

