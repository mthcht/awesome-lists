rule Trojan_Win32_Barlaiy_A_2147717398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Barlaiy.A!dha"
        threat_id = "2147717398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Barlaiy"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 bf 58 07 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {6a 02 68 fc fe ff ff 53 e8 e3 14 00 00 bf 04 01 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "Rundll32.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

