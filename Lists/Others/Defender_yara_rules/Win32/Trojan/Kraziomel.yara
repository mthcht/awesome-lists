rule Trojan_Win32_Kraziomel_C_2147682715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kraziomel.C"
        threat_id = "2147682715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kraziomel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 62 6c 65 c7 45 ?? 2e 79 74 00 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 4e 04 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 4e 0c e8}  //weight: 1, accuracy: Low
        $x_1_2 = ">>>ID: BitFORCE SHA256 Version 1.0>>>" ascii //weight: 1
        $x_1_3 = "10fa597b30f766c011dfd84e881360a50aa927954157ee47" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

