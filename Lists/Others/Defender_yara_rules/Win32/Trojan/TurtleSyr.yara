rule Trojan_Win32_TurtleSyr_A_2147781990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurtleSyr.A!dha"
        threat_id = "2147781990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurtleSyr"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Failed to decode the provided shellcode" ascii //weight: 1
        $x_1_2 = "Successfully Injected." ascii //weight: 1
        $x_1_3 = "Could Not Write To Remote Process" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

