rule Trojan_Win32_NSISInjectorInject_EM_2147847285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInjectorInject.EM!MTB"
        threat_id = "2147847285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInjectorInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {16 16 16 7a 00 00 00 0d 00 00 00 21 00 00 00 43 5d 5d 5d ea 8f 8f 8f fa 9b 9b 9b fb 9c 9c 9c fc 9a 9a 9a fb b0 b0 b0 fb b1 b1 b1 fe 1a 1a 1a ff 17 17 17 ff 1b 1b 1b ff 1e 1e 1e ff 2d 2d 2d ff 41 41 41 ff 4d 4d 4d ff 4f 4f 4f ff 50 50 50 ff 50 50 50 ff 51 51 51 ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

