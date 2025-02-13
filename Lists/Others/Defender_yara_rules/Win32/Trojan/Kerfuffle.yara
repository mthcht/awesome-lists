rule Trojan_Win32_Kerfuffle_C_2147744095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kerfuffle.C!dha"
        threat_id = "2147744095"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kerfuffle"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dll_wWinMain" ascii //weight: 1
        $x_1_2 = "InstLspDll.dll" ascii //weight: 1
        $x_1_3 = "ImmWin32.ime" ascii //weight: 1
        $x_1_4 = "msdtc64.sys" ascii //weight: 1
        $x_2_5 = "conime1.dat" ascii //weight: 2
        $x_1_6 = "WinAdv.bak" ascii //weight: 1
        $x_2_7 = {54 65 6d 70 5c 00 00 00 6b 65 6c 6c 2e 64 61 74}  //weight: 2, accuracy: High
        $x_2_8 = {54 65 6d 70 5c 00 00 00 77 6e 64 70 77 64}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

