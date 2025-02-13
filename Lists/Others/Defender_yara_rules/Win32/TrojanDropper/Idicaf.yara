rule TrojanDropper_Win32_Idicaf_C_2147610458_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Idicaf.C"
        threat_id = "2147610458"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Idicaf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "del %%0" ascii //weight: 1
        $x_1_2 = "conime.exe" ascii //weight: 1
        $x_1_3 = "\\svchost.exe" ascii //weight: 1
        $x_1_4 = "%s\\%d_create" ascii //weight: 1
        $x_1_5 = "attrib -a -r -s -h \"%s\"" ascii //weight: 1
        $x_1_6 = "if exist \"%s\" goto selfkill" ascii //weight: 1
        $x_1_7 = "%s\\%d_selfdel.bat" ascii //weight: 1
        $x_1_8 = "%s\\%d_install.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

