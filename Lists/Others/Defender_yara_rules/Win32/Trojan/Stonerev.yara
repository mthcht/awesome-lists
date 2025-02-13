rule Trojan_Win32_Stonerev_A_2147667451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stonerev.A"
        threat_id = "2147667451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stonerev"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 53 54 4f 4e 45 53 00}  //weight: 1, accuracy: High
        $x_1_2 = "exe.yartsR" ascii //weight: 1
        $x_1_3 = "s%\\pmeT\\SWODNIW\\:C" ascii //weight: 1
        $x_1_4 = "p\\WinUpdate.tmp" ascii //weight: 1
        $x_1_5 = "LoaderMira" ascii //weight: 1
        $x_1_6 = {ff 72 c6 85 ?? ff ff ff 5c c6 85 ?? ff ff ff 63 c6 85 ?? ff ff ff 61 c6 85 ?? ff ff ff 72 c6 85 ?? ff ff ff 73 c6 85 ?? ff ff ff 73 c6 85 ?? ff ff ff 2e c6 85 ?? ff ff ff 65 c6 85 ?? ff ff ff 78 c6 85 ?? ff ff ff 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

