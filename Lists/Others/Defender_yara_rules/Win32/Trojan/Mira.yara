rule Trojan_Win32_Mira_D_2147730080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mira.D!MTB"
        threat_id = "2147730080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mira"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 4d 00 69 00 72 00 61 00 20 00 4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 00 00 00 00 38 00 0a 00 01 00 50 00 72}  //weight: 1, accuracy: High
        $x_1_2 = "\\All Users\\Application Data\\Saaaalamm\\Mira.h" ascii //weight: 1
        $x_1_3 = "/mnt/samo/mingw/msys/mthr_stub.c" ascii //weight: 1
        $x_1_4 = "\\All Users\\Application Data\\xinsbp.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

