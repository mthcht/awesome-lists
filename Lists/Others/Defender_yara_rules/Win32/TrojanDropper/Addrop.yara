rule TrojanDropper_Win32_Addrop_C_2147731315_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Addrop.C!bit"
        threat_id = "2147731315"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Addrop"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-p\"P1r0t" wide //weight: 1
        $x_1_2 = "kaspersky" wide //weight: 1
        $x_1_3 = "{tmp}\\misc.res" wide //weight: 1
        $x_1_4 = "{tmp}\\form.exe" wide //weight: 1
        $x_1_5 = "{tmp}\\misc.xml" wide //weight: 1
        $x_1_6 = "{app}\\license.txt" wide //weight: 1
        $x_1_7 = "v=1&tid=%s&cid=%s&t=event&ec=%s&ea=%s" wide //weight: 1
        $x_1_8 = "WinHttp.WinHttpRequest.5.1" wide //weight: 1
        $x_1_9 = "http://www.worldofbooks.org/getchannel?" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

