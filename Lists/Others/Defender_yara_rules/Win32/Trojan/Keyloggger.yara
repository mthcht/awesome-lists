rule Trojan_Win32_Keyloggger_A_2147624741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keyloggger.A"
        threat_id = "2147624741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keyloggger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%CD%\\autorun.inf /Y /h /k /r %WINDIR%" ascii //weight: 1
        $x_1_2 = "[*]Keylog" ascii //weight: 1
        $x_1_3 = {83 d8 03 b9 20 00 00 00 2d ?? ?? ?? ?? 66 89 88 ?? ?? ?? ?? bb 5b 2a 5d 20 bf 56 65 6e 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

