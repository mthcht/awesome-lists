rule Worm_Win32_Drolnux_C_2147681148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Drolnux.C"
        threat_id = "2147681148"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Drolnux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CeyLucker" ascii //weight: 1
        $x_1_2 = "set Mr9=del" wide //weight: 1
        $x_1_3 = "%Mr9% /s /f /a /q" wide //weight: 1
        $x_1_4 = "ashcv.exe" wide //weight: 1
        $x_1_5 = "SHDeAthMrLiNuxYwZJk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Drolnux_B_2147681149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Drolnux.B"
        threat_id = "2147681149"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Drolnux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CeyLucker" ascii //weight: 1
        $x_1_2 = "set Mr9=del" ascii //weight: 1
        $x_1_3 = "%Mr9% /s /f /a /q" ascii //weight: 1
        $x_1_4 = "ashcv.exe" ascii //weight: 1
        $x_1_5 = "COM7.EXE" ascii //weight: 1
        $x_1_6 = "bilbilal.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

