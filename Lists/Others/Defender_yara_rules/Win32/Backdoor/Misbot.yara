rule Backdoor_Win32_Misbot_A_2147663871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Misbot.A"
        threat_id = "2147663871"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Misbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {99 f7 f9 89 d6 e8 ?? ?? ?? ?? ba 0a 00 00 00 89 d1 99 f7 f9 89 d3 c7 04 24 96 00 00 00 e8}  //weight: 2, accuracy: Low
        $x_1_2 = "C:\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\A%li.exe" ascii //weight: 1
        $x_1_3 = "%s\\Bitcoin\\wallet.dat" ascii //weight: 1
        $x_1_4 = {44 44 6f 53 20 74 68 72 65 61 64 20 74 65 72 6d 69 6e 61 74 69 6e 67 21 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

