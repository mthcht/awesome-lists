rule Trojan_Win32_Zeeborot_A_2147672640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zeeborot.A"
        threat_id = "2147672640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zeeborot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "socks4a://127.0.0.1:9050',0 " ascii //weight: 1
        $x_1_2 = {64 6f 77 6e 6c 6f 61 64 2e 6d 65 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = "Skynet_0." ascii //weight: 1
        $x_1_4 = "--HiddenServiceDir \"%s\\hidden_service\" --HiddenServicePort \"55080 127.0.0.1:55080\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

