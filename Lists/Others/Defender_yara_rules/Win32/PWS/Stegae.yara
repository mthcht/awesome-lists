rule PWS_Win32_Stegae_A_2147650261_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Stegae.A"
        threat_id = "2147650261"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Stegae"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 67 61 74 65 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_2 = "\\Pbk\\rasphone.pbk" ascii //weight: 1
        $x_1_3 = "RasDialParams!%s#0" wide //weight: 1
        $x_1_4 = {6a 02 66 89 45 ?? ff 15 ?? ?? ?? ?? 89 (45 ??|85 ?? ??) 83 f8 ff 75 ?? 32 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

