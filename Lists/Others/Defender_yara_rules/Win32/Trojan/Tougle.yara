rule Trojan_Win32_Tougle_A_2147735477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tougle.A!bit"
        threat_id = "2147735477"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tougle"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 2f 63 68 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = "/sc ONLOGON /delay 0000:05 /" ascii //weight: 1
        $x_1_3 = "abcdefghijklmnopqrstuvwxyzaaaeeeooouuuiiiyyy" ascii //weight: 1
        $x_1_4 = "cmd /c \"\"%s%s%s%s.exe" ascii //weight: 1
        $x_1_5 = {00 62 69 74 73 61 64 6d 69 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

