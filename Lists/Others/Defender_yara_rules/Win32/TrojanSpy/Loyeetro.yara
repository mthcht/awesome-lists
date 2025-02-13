rule TrojanSpy_Win32_Loyeetro_A_2147721656_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Loyeetro.A"
        threat_id = "2147721656"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Loyeetro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Log Started] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]" ascii //weight: 1
        $x_1_2 = "{GET %s HTTP/1.1" ascii //weight: 1
        $x_1_3 = "%N\\%N.UAU" ascii //weight: 1
        $x_1_4 = "start /b \"\" cmd /c del \"%%~f0\"&exit /b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Loyeetro_B_2147724431_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Loyeetro.B!bit"
        threat_id = "2147724431"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Loyeetro"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "start /b \"\" cmd /c del \"%%~f0\"&exit /b" ascii //weight: 1
        $x_1_2 = "[Log Started] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]" ascii //weight: 1
        $x_1_3 = "%s\\%s.bat" ascii //weight: 1
        $x_1_4 = "GET %s HTTP/1.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Loyeetro_KS_2147758886_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Loyeetro.KS"
        threat_id = "2147758886"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Loyeetro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shutup_And_Fuckof.dll" ascii //weight: 1
        $x_2_2 = "\\Users\\Raz\\Desktop\\StudentProject\\Shutup_And_Fuckof\\obj\\Debug\\Shutup_And_Fuckof.pdb" ascii //weight: 2
        $x_1_3 = "I_DK_WHAT_U_DOING_HERE_FUCKOFF" ascii //weight: 1
        $x_1_4 = "StudentProject.Properties.Resources.resources" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

